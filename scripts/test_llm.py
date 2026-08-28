"""Diagnose the LLM endpoint: key validity, available free models, one test call.

  python scripts/test_llm.py [model_id]
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

import requests

BASE = os.environ.get("LLM_BASE_URL", "").rstrip("/")
KEY = os.environ.get("LLM_API_KEY", "")


def main():
    if not BASE or not KEY:
        sys.exit("LLM_BASE_URL / LLM_API_KEY not set in .env")
    headers = {"Authorization": f"Bearer {KEY}"}

    # 1. key status (OpenRouter-specific endpoint; harmless 404 elsewhere)
    r = requests.get(f"{BASE}/key", headers=headers, timeout=30)
    print(f"--- key check: HTTP {r.status_code}")
    print(r.text[:400], "\n")

    # 2. models visible TO THIS KEY
    r = requests.get(f"{BASE}/models", headers=headers, timeout=60)
    r.raise_for_status()
    ids = [m["id"] for m in r.json()["data"]]
    free = [i for i in ids if i.endswith(":free")]
    print(f"--- {len(ids)} models visible, {len(free)} free:")
    for f in sorted(free):
        print("   ", f)

    # 3. one test completion
    model = sys.argv[1] if len(sys.argv) > 1 else (free[0] if free else ids[0])
    print(f"\n--- test completion with {model}")
    r = requests.post(f"{BASE}/chat/completions", headers=headers, timeout=120,
                      json={"model": model,
                            "messages": [{"role": "user",
                                          "content": "Reply with exactly: OK"}]})
    print(f"HTTP {r.status_code}")
    print(r.text[:500])


if __name__ == "__main__":
    main()
