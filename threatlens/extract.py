"""LLM-based structured CTI extraction.

The prompt asks for atomic claims with quoted evidence spans. The verifier
(verify.py) later decides what was hallucinated — extraction itself never
filters, so we measure the model's raw behaviour.
"""
from __future__ import annotations

import logging

from .llm import LLMClient, parse_json_loosely
from .schema import Claim, ClaimType, ExtractionResult, Report

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a cyber threat intelligence analyst. Extract structured intelligence
from the threat report provided by the user. Respond with ONLY a JSON object,
no markdown, with this exact schema:

{
  "summary": "<2-3 sentence summary>",
  "cves": [{"id": "CVE-YYYY-NNNN", "product": "<affected product or null>", "evidence": "<verbatim quote from report>"}],
  "iocs": [{"type": "ip|domain|url|hash|email", "value": "<indicator>", "evidence": "<verbatim quote>"}],
  "attack_techniques": [{"id": "TNNNN or TNNNN.NNN", "name": "<official MITRE ATT&CK technique name>", "evidence": "<verbatim quote>"}],
  "threat_actors": [{"name": "<actor/group name>", "evidence": "<verbatim quote>"}],
  "malware": [{"name": "<malware family>", "evidence": "<verbatim quote>"}]
}

Rules:
- Only include items the report supports. Use empty arrays when nothing is found.
- "evidence" must be copied verbatim from the report text.
- For attack_techniques, give the official MITRE ATT&CK ID and name.
"""

_IOC_TYPE_MAP = {
    "ip": ClaimType.IOC_IP, "ipv4": ClaimType.IOC_IP, "ipv6": ClaimType.IOC_IP,
    "domain": ClaimType.IOC_DOMAIN, "hostname": ClaimType.IOC_DOMAIN,
    "url": ClaimType.IOC_URL,
    "hash": ClaimType.IOC_HASH, "md5": ClaimType.IOC_HASH,
    "sha1": ClaimType.IOC_HASH, "sha256": ClaimType.IOC_HASH,
    "email": ClaimType.IOC_EMAIL,
}

MAX_CHARS = 24000  # ~6k tokens of report text; configurable truncation


def extract(report: Report, client: LLMClient, run_index: int = 0) -> ExtractionResult:
    text = report.text[:MAX_CHARS]
    user = f"Title: {report.title}\nPublished: {report.published}\n\nReport:\n{text}"
    try:
        raw = client.chat(SYSTEM_PROMPT, user, json_mode=True)
    except Exception as e:  # network/model failure — record, don't fabricate
        log.error("LLM call failed for %s: %s", report.report_id, e)
        return ExtractionResult(report.report_id, client.model, run_index,
                                claims=[], error=str(e))
    try:
        data = parse_json_loosely(raw)
    except (ValueError, Exception) as e:
        log.warning("Unparseable LLM output for %s: %s", report.report_id, e)
        return ExtractionResult(report.report_id, client.model, run_index,
                                claims=[], raw_response=raw,
                                error=f"json_parse: {e}")

    claims: list[Claim] = []
    for c in data.get("cves") or []:
        if isinstance(c, dict) and c.get("id"):
            claims.append(Claim(ClaimType.CVE, str(c["id"]).upper().strip(),
                                label=c.get("product"), context=c.get("evidence")))
    for c in data.get("iocs") or []:
        if isinstance(c, dict) and c.get("value"):
            ct = _IOC_TYPE_MAP.get(str(c.get("type", "")).lower())
            if ct:
                claims.append(Claim(ct, str(c["value"]).strip(),
                                    context=c.get("evidence")))
    for c in data.get("attack_techniques") or []:
        if isinstance(c, dict) and c.get("id"):
            claims.append(Claim(ClaimType.ATTACK_TECHNIQUE,
                                str(c["id"]).upper().strip(),
                                label=c.get("name"), context=c.get("evidence")))
    for c in data.get("threat_actors") or []:
        if isinstance(c, dict) and c.get("name"):
            claims.append(Claim(ClaimType.THREAT_ACTOR, str(c["name"]).strip(),
                                context=c.get("evidence")))
    for c in data.get("malware") or []:
        if isinstance(c, dict) and c.get("name"):
            claims.append(Claim(ClaimType.MALWARE, str(c["name"]).strip(),
                                context=c.get("evidence")))

    return ExtractionResult(report.report_id, client.model, run_index,
                            claims=claims, summary=data.get("summary"),
                            raw_response=raw)
