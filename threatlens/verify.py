"""Claim-level hallucination detector — the core contribution.

For each Claim, assign a Verdict (see schema.Verdict / RESEARCH.md §4):
  FABRICATED   entity does not exist in any authority
  UNGROUNDED   exists, but not supported by the source document text
  MISLABELED   exists + grounded, but LLM attached wrong metadata
  VERIFIED     all checks pass
  UNVERIFIABLE authority unavailable (e.g. NVD API down) — never guessed

Authorities: NVD API (CVEs), MITRE ATT&CK STIX (techniques, actors, malware),
and the source document itself (provenance for every claim type).
"""
from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

from .attack import AttackKB
from .nvd import NVDClient
from .schema import (ATTACK_ID_RE, CVE_RE, Claim, ClaimType, IOC_PATTERNS,
                     Report, Verdict, refang)

log = logging.getLogger(__name__)


class Verifier:
    def __init__(self, attack_kb: AttackKB, nvd: NVDClient | None = None):
        self.kb = attack_kb
        self.nvd = nvd or NVDClient()
        self._src = ""

    def verify_all(self, claims: list[Claim], report: Report) -> list[Claim]:
        src = refang(report.text).lower()
        self._src = src
        for claim in claims:
            try:
                self._verify(claim, src)
            except Exception as e:  # never let one claim kill the run
                log.error("verify error on %s: %s", claim.value, e)
                claim.verdict = Verdict.UNVERIFIABLE
                claim.checks["error"] = str(e)
        return claims

    # ------------------------------------------------------------------ #

    def _verify(self, claim: Claim, src: str):
        grounded = self._grounded(claim, src)
        claim.checks["in_source"] = grounded

        if claim.claim_type == ClaimType.CVE:
            self._verify_cve(claim, grounded)
        elif claim.claim_type == ClaimType.ATTACK_TECHNIQUE:
            self._verify_technique(claim, grounded)
        elif claim.claim_type == ClaimType.THREAT_ACTOR:
            self._verify_actor(claim, grounded)
        elif claim.claim_type == ClaimType.MALWARE:
            self._verify_malware(claim, grounded)
        elif claim.claim_type in IOC_PATTERNS:
            self._verify_ioc(claim, grounded)
        else:
            claim.verdict = Verdict.UNVERIFIABLE

    def _grounded(self, claim: Claim, src: str) -> bool:
        """Is the claimed value literally present in the (refanged) source?"""
        return refang(claim.value).lower() in src

    def _verify_cve(self, claim: Claim, grounded: bool):
        nvd = self.nvd.lookup(claim.value)
        if nvd is None:
            claim.verdict = Verdict.UNVERIFIABLE
            claim.checks["nvd"] = "api_unavailable"
            return
        claim.checks["nvd_exists"] = nvd.get("exists", False)
        if not nvd.get("exists"):
            claim.checks["nvd_reason"] = nvd.get("reason")
            # Registry lag is real: CISA ICS advisories cite CVEs that appear
            # in neither NVD nor CVE.org for days (observed 2026-06-12: 9 of
            # 11 CVEs in same-day advisories unregistered). A CVE quoted
            # verbatim from the source is not a hallucination — but it cannot
            # be confirmed either -> UNVERIFIABLE. Only an ungrounded AND
            # unregistered CVE is FABRICATED.
            claim.verdict = (Verdict.UNVERIFIABLE if grounded
                             else Verdict.FABRICATED)
            return
        if not grounded:
            # Real CVE, but the source never mentions it: parametric-memory
            # import — the provenance failure G2 in RESEARCH.md.
            claim.verdict = Verdict.UNGROUNDED
            return
        # metadata consistency: product label vs NVD description.
        # Token overlap, NOT string similarity — a short label vs a long
        # description paragraph always scores ~0 on SequenceMatcher, which
        # mass-flagged correct products ("Google Chromium V8", "Hitachi
        # Energy RTU500", ...) as MISLABELED (audit finding, 2026-06-18).
        # Skip when description is empty (e.g. RESERVED CVE.org records).
        desc = (nvd.get("description") or "").lower()
        if claim.label and desc:
            tokens = [t for t in re.split(r"[^a-z0-9]+", claim.label.lower())
                      if len(t) > 1]
            overlap = (sum(t in desc for t in tokens) / len(tokens)
                       if tokens else 1.0)
            claim.checks["product_token_overlap"] = round(overlap, 2)
            if overlap < 0.34:
                # Supply-chain caveat (audit finding, 2026-07-08): ICS
                # advisories list the AFFECTED product ("Hitachi ITT600")
                # while NVD describes the vulnerable COMPONENT (libexpat).
                # A label grounded in the source text is faithful extraction,
                # not a mislabel — only flag labels absent from BOTH.
                src_overlap = (sum(t in self._src for t in tokens)
                               / len(tokens) if tokens else 1.0)
                claim.checks["product_in_source_overlap"] = round(src_overlap, 2)
                if src_overlap < 0.34:
                    claim.verdict = Verdict.MISLABELED
                    return
                claim.checks["supply_chain_mismatch"] = True
        claim.verdict = Verdict.VERIFIED

    def _verify_technique(self, claim: Claim, grounded: bool):
        tid = claim.value.upper()
        if not ATTACK_ID_RE.fullmatch(tid) or not self.kb.is_valid_technique(tid):
            claim.verdict = Verdict.FABRICATED
            claim.checks["valid_attack_id"] = False
            return
        claim.checks["valid_attack_id"] = True
        official = self.kb.technique_name(tid) or ""
        claim.checks["official_name"] = official
        if claim.label:
            label = claim.label.lower()
            # Models legitimately write "Parent Technique: Sub-technique"
            # (e.g. "Unsecured Credentials: Private Keys" for T1552.004).
            # Compare both the full label and the part after the last colon.
            candidates = [label, label.rsplit(":", 1)[-1].strip()]
            sim = max(_similar(c, official.lower()) for c in candidates)
            claim.checks["name_similarity"] = round(sim, 3)
            if sim < 0.55:
                # Real ID, wrong name attached — classic LLM confabulation.
                claim.verdict = Verdict.MISLABELED
                return
        # Technique IDs are analyst inferences; most reports don't quote IDs
        # verbatim. Grounding check here = evidence span must exist in source.
        ev = (claim.context or "").strip().lower()
        ev_ok = bool(ev) and ev[:120] in self._src
        claim.checks["evidence_in_source"] = ev_ok
        claim.verdict = Verdict.VERIFIED if (grounded or ev_ok) else Verdict.UNGROUNDED

    def _verify_actor(self, claim: Claim, grounded: bool):
        canon = self.kb.resolve_actor(claim.value)
        claim.checks["attack_canonical"] = canon
        if canon is None:
            # Not in ATT&CK: could be new/unnamed group. Existence authority is
            # weak here, so: in source -> verified-as-grounded; else fabricated.
            claim.verdict = Verdict.VERIFIED if grounded else Verdict.FABRICATED
            return
        claim.verdict = Verdict.VERIFIED if grounded else Verdict.UNGROUNDED

    def _verify_malware(self, claim: Claim, grounded: bool):
        claim.checks["in_attack_kb"] = self.kb.is_known_malware(claim.value)
        if grounded:
            claim.verdict = Verdict.VERIFIED
        elif claim.checks["in_attack_kb"]:
            claim.verdict = Verdict.UNGROUNDED
        else:
            claim.verdict = Verdict.FABRICATED

    def _verify_ioc(self, claim: Claim, grounded: bool):
        pattern = IOC_PATTERNS[claim.claim_type]
        wellformed = bool(pattern.fullmatch(refang(claim.value)))
        claim.checks["wellformed"] = wellformed
        if not wellformed:
            # Malformed value that IS present in the source = the model
            # garbled the type/format of a real artifact (e.g. a SHA1 line
            # extracted as an "ip") -> MISLABELED, not FABRICATED.
            # Observed in practice with gpt-oss-20b, 2026-06-12.
            claim.verdict = Verdict.MISLABELED if grounded else Verdict.FABRICATED
            return
        # IoCs MUST be verbatim from the source — there is no legitimate way
        # for a model to "know" a hash or C2 IP that the report doesn't state.
        claim.verdict = Verdict.VERIFIED if grounded else Verdict.UNGROUNDED


def _similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


# ---------------------------------------------------------------- metrics

def summarize(claims: list[Claim]) -> dict:
    """Aggregate verdict counts + hallucination rate for a set of claims."""
    counts: dict[str, int] = {}
    for c in claims:
        v = c.verdict.value if c.verdict else "none"
        counts[v] = counts.get(v, 0) + 1
    total = len(claims)
    halluc = sum(counts.get(k, 0) for k in ("fabricated", "ungrounded", "mislabeled"))
    verifiable = total - counts.get("unverifiable", 0)
    return {
        "total_claims": total,
        "verdicts": counts,
        "hallucination_rate": round(halluc / verifiable, 4) if verifiable else None,
    }
