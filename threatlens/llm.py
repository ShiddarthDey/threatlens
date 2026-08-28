"""Provider-agnostic LLM client.

Works with:
  - Ollama local server (default, http://localhost:11434) — Llama 3, Mistral, Qwen
  - Any OpenAI-compatible endpoint (OpenRouter, Groq, Together, vLLM, ...) via env:
        LLM_BASE_URL, LLM_API_KEY

Direct HTTP (no LangChain): fewer deps, fully reproducible request logging.
"""
from __future__ import annotations

import json
import logging
import os
import time

import requests

log = logging.getLogger(__name__)


class LLMClient:
    def __init__(
        self,
        model: str = "llama3:8b",
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.0,
        timeout: int = 300,
        seed: int | None = 42,
        retries: int = 3,
    ):
        self.retries = retries
        self.model = model
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL")
                         or "http://localhost:11434").rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY")
        self.temperature = temperature
        self.timeout = timeout
        self.seed = seed
        # Ollama native if no /v1 in URL and no key; else OpenAI-compatible.
        self.is_ollama = "11434" in self.base_url and not self.api_key

    def chat(self, system: str, user: str, json_mode: bool = True) -> str:
        if self.is_ollama:
            return self._ollama(system, user, json_mode)
        return self._openai_compat(system, user, json_mode)

    def _ollama(self, system: str, user: str, json_mode: bool) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": self.temperature,
                        **({"seed": self.seed} if self.seed is not None else {})},
        }
        if json_mode:
            payload["format"] = "json"
        r = requests.post(f"{self.base_url}/api/chat", json=payload,
                          timeout=self.timeout)
        r.raise_for_status()
        return r.json()["message"]["content"]

    def _openai_compat(self, system: str, user: str, json_mode: bool) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        r = self._post_with_retry(payload, headers)
        if r.status_code == 400 and json_mode:
            # some providers/models (incl. a few on OpenRouter) reject
            # response_format — retry once without it; parse_json_loosely
            # downstream tolerates fenced/loose JSON.
            log.info("response_format rejected by %s; retrying without",
                     self.model)
            payload.pop("response_format", None)
            r = self._post_with_retry(payload, headers)
        if not r.ok:
            # surface the provider's error body — raise_for_status drops it
            raise RuntimeError(f"HTTP {r.status_code} from {self.base_url}: "
                               f"{r.text[:300]}")
        msg = r.json()["choices"][0]["message"]
        content = msg.get("content")
        if not content:
            # reasoning models (e.g. gpt-oss) sometimes return the answer in
            # "reasoning" with an empty "content"
            content = msg.get("reasoning") or ""
        if not content.strip():
            raise RuntimeError(f"{self.model} returned empty content")
        return content

    def _post_with_retry(self, payload: dict, headers: dict):
        """POST with exponential backoff on 429 (free tiers, upstream limits)."""
        r = None
        for attempt in range(self.retries + 1):
            r = requests.post(f"{self.base_url}/chat/completions",
                              json=payload, headers=headers,
                              timeout=self.timeout)
            if r.status_code != 429 or attempt == self.retries:
                return r
            wait = int(r.headers.get("Retry-After") or 0) or 15 * (attempt + 1)
            log.info("429 for %s; retry %d/%d in %ds", self.model,
                     attempt + 1, self.retries, wait)
            time.sleep(wait)
        return r


def parse_json_loosely(raw: str | None) -> dict:
    """Parse LLM JSON output, tolerating fences, trailing prose, and raw
    control characters inside strings (strict=False)."""
    if not raw:
        raise ValueError("empty LLM output")
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("```")[1]
        if s.startswith("json"):
            s = s[4:]
    # take outermost {...}
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object in LLM output: {raw[:200]!r}")
    return json.loads(s[start:end + 1], strict=False)
