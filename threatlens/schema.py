"""Core data structures for ThreatLens."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Four-way hallucination taxonomy (see RESEARCH.md §4)."""
    FABRICATED = "fabricated"      # entity does not exist in any authority
    UNGROUNDED = "ungrounded"      # exists, but not supported by source document
    MISLABELED = "mislabeled"      # exists + grounded, but wrong metadata attached
    VERIFIED = "verified"          # all checks pass
    UNVERIFIABLE = "unverifiable"  # no authority available for this claim type


class ClaimType(str, Enum):
    CVE = "cve"
    IOC_IP = "ioc_ip"
    IOC_DOMAIN = "ioc_domain"
    IOC_URL = "ioc_url"
    IOC_HASH = "ioc_hash"
    IOC_EMAIL = "ioc_email"
    ATTACK_TECHNIQUE = "attack_technique"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"


@dataclass
class Report:
    """A normalized threat report from any source."""
    source: str                 # e.g. "cisa", "otx"
    source_id: str              # advisory ID / pulse ID
    title: str
    url: str
    published: str              # ISO 8601
    text: str                   # full plain text body
    fetched_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def report_id(self) -> str:
        return hashlib.sha256(f"{self.source}:{self.source_id}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["report_id"] = self.report_id
        return d


@dataclass
class Claim:
    """One atomic claim extracted by the LLM."""
    claim_type: ClaimType
    value: str                          # e.g. "CVE-2024-3400", "T1566.001"
    label: str | None = None            # e.g. technique name, product, actor alias
    context: str | None = None          # LLM-quoted supporting span from source
    # filled by the verifier:
    verdict: Verdict | None = None
    checks: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["claim_type"] = self.claim_type.value
        d["verdict"] = self.verdict.value if self.verdict else None
        return d


@dataclass
class ExtractionResult:
    report_id: str
    model: str
    run_index: int
    claims: list[Claim]
    summary: str | None = None
    raw_response: str | None = None
    error: str | None = None
    extracted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "model": self.model,
            "run_index": self.run_index,
            "claims": [c.to_dict() for c in self.claims],
            "summary": self.summary,
            "error": self.error,
            "extracted_at": self.extracted_at,
        }


# ---- IoC regexes (shared by extractor validation + verifier provenance) ----

def refang(text: str) -> str:
    """Normalize defanged IoCs: hxxp -> http, [.] -> ., (.) -> ., [@] -> @."""
    out = text
    out = re.sub(r"h[xX]{2}p(s?)://", r"http\1://", out)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    out = out.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    return out


IOC_PATTERNS: dict[ClaimType, re.Pattern] = {
    ClaimType.IOC_IP: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    ClaimType.IOC_DOMAIN: re.compile(
        r"\b(?=.{4,253}\b)((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,18})\b"
    ),
    ClaimType.IOC_URL: re.compile(r"\bhttps?://[^\s\"'<>\)\]]+", re.IGNORECASE),
    ClaimType.IOC_HASH: re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"),
    ClaimType.IOC_EMAIL: re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
