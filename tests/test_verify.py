"""Unit tests for the verifier — runs fully offline.

A tiny fake ATT&CK KB and a stubbed NVD client let us test every verdict
path deterministically without network access.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threatlens.schema import Claim, ClaimType, Report, Verdict, refang  # noqa: E402
from threatlens.verify import Verifier, summarize  # noqa: E402


class FakeKB:
    techniques = {"T1566.001": "Spearphishing Attachment", "T1059": "Command and Scripting Interpreter"}
    def is_valid_technique(self, tid): return tid.upper() in self.techniques
    def technique_name(self, tid): return self.techniques.get(tid.upper())
    def resolve_actor(self, name):
        return {"apt29": "APT29", "cozy bear": "APT29"}.get(name.lower())
    def is_known_malware(self, name): return name.lower() in {"emotet"}


class FakeNVD:
    """CVE-2021-44228 exists (Log4Shell); everything else doesn't."""
    def lookup(self, cve_id):
        if cve_id.upper() == "CVE-2021-44228":
            return {"exists": True,
                    "description": "Apache Log4j2 JNDI features used in configuration..."}
        if cve_id.upper() == "CVE-2099-99999":
            return None  # simulate API outage
        return {"exists": False, "reason": "not_in_nvd"}


REPORT = Report(
    source="test", source_id="t1", title="t", url="http://x", published="2026-01-01",
    text=("Actors exploited CVE-2021-44228 in Apache Log4j2. C2 at 203.0.113[.]7 "
          "and hxxps://evil.example[.]com/payload. Hash "
          "d41d8cd98f00b204e9800998ecf8427e observed. APT29 used spearphishing "
          "attachments to deliver Emotet. CVE-2026-11111 is pending analysis. "
          "ContosoCam 3000 devices are affected."),
)


def V():
    return Verifier(FakeKB(), FakeNVD())


def run_one(claim):
    return V().verify_all([claim], REPORT)[0]


def test_refang():
    assert refang("203.0.113[.]7") == "203.0.113.7"
    assert refang("hxxps://evil.example[.]com") == "https://evil.example.com"


def test_cve_verified():
    c = run_one(Claim(ClaimType.CVE, "CVE-2021-44228", label="Log4j2"))
    assert c.verdict == Verdict.VERIFIED


def test_cve_product_partial_token_match_verified():
    """Correct product phrased differently than the NVD description must not
    be MISLABELED (audit finding: 'Google Chromium V8' style labels)."""
    c = run_one(Claim(ClaimType.CVE, "CVE-2021-44228",
                      label="Apache Log4j2 Library"))
    assert c.verdict == Verdict.VERIFIED


def test_cve_product_wrong_mislabeled():
    c = run_one(Claim(ClaimType.CVE, "CVE-2021-44228",
                      label="Windows SMB Server"))
    assert c.verdict == Verdict.MISLABELED


def test_cve_supply_chain_product_verified():
    """Affected product (from advisory) differs from vulnerable component
    (NVD description) — SBOM case. Label grounded in source -> VERIFIED,
    flagged supply_chain_mismatch (audit finding, 2026-07-08)."""
    c = run_one(Claim(ClaimType.CVE, "CVE-2021-44228",
                      label="ContosoCam 3000"))
    assert c.verdict == Verdict.VERIFIED
    assert c.checks.get("supply_chain_mismatch") is True


def test_cve_fabricated():
    c = run_one(Claim(ClaimType.CVE, "CVE-2024-99999"))
    assert c.verdict == Verdict.FABRICATED


def test_cve_grounded_but_unregistered_is_unverifiable():
    """CVE quoted verbatim from the source but absent from NVD/CVE.org
    (registry lag, observed with fresh CISA ICS advisories) -> UNVERIFIABLE,
    not FABRICATED."""
    c = run_one(Claim(ClaimType.CVE, "CVE-2026-11111"))
    assert c.verdict == Verdict.UNVERIFIABLE


def test_cve_ungrounded():
    """Real CVE that the source never mentions -> parametric import."""
    class NVDAllExist(FakeNVD):
        def lookup(self, cve_id):
            return {"exists": True, "description": "something"}
    v = Verifier(FakeKB(), NVDAllExist())
    c = v.verify_all([Claim(ClaimType.CVE, "CVE-2020-1472")], REPORT)[0]
    assert c.verdict == Verdict.UNGROUNDED


def test_cve_api_down_is_unverifiable_not_fabricated():
    c = run_one(Claim(ClaimType.CVE, "CVE-2099-99999"))
    assert c.verdict == Verdict.UNVERIFIABLE


def test_ioc_ip_verified_despite_defang():
    c = run_one(Claim(ClaimType.IOC_IP, "203.0.113.7"))
    assert c.verdict == Verdict.VERIFIED


def test_ioc_ip_ungrounded():
    c = run_one(Claim(ClaimType.IOC_IP, "198.51.100.99"))
    assert c.verdict == Verdict.UNGROUNDED


def test_ioc_malformed_fabricated():
    c = run_one(Claim(ClaimType.IOC_IP, "999.999.1.1"))
    assert c.verdict == Verdict.FABRICATED


def test_ioc_malformed_but_grounded_mislabeled():
    """Artifact text present in source but garbled type/format (seen with
    gpt-oss-20b: a SHA1 line extracted as an 'ip') -> MISLABELED."""
    c = run_one(Claim(ClaimType.IOC_IP, "203.0.113"))  # truncated real IP
    assert c.verdict == Verdict.MISLABELED


def test_ioc_hash_verified():
    c = run_one(Claim(ClaimType.IOC_HASH, "d41d8cd98f00b204e9800998ecf8427e"))
    assert c.verdict == Verdict.VERIFIED


def test_technique_verified():
    c = run_one(Claim(ClaimType.ATTACK_TECHNIQUE, "T1566.001",
                      label="Spearphishing Attachment",
                      context="APT29 used spearphishing attachments"))
    assert c.verdict == Verdict.VERIFIED


def test_technique_fabricated_id():
    c = run_one(Claim(ClaimType.ATTACK_TECHNIQUE, "T9999"))
    assert c.verdict == Verdict.FABRICATED


def test_technique_mislabeled():
    c = run_one(Claim(ClaimType.ATTACK_TECHNIQUE, "T1566.001",
                      label="Process Injection"))
    assert c.verdict == Verdict.MISLABELED


def test_technique_parent_prefixed_label_not_mislabeled():
    """'Parent: Sub' label format is correct usage (seen with Nemotron:
    'Unsecured Credentials: Private Keys' for T1552.004)."""
    c = run_one(Claim(ClaimType.ATTACK_TECHNIQUE, "T1566.001",
                      label="Phishing: Spearphishing Attachment",
                      context="APT29 used spearphishing attachments"))
    assert c.verdict == Verdict.VERIFIED


def test_actor_verified():
    c = run_one(Claim(ClaimType.THREAT_ACTOR, "APT29"))
    assert c.verdict == Verdict.VERIFIED


def test_actor_known_but_ungrounded():
    c = run_one(Claim(ClaimType.THREAT_ACTOR, "Cozy Bear"))
    # alias resolves to APT29 but "cozy bear" not in source text
    assert c.verdict == Verdict.UNGROUNDED


def test_actor_unknown_and_ungrounded_fabricated():
    c = run_one(Claim(ClaimType.THREAT_ACTOR, "Crimson Walrus Group"))
    assert c.verdict == Verdict.FABRICATED


def test_malware_verified():
    c = run_one(Claim(ClaimType.MALWARE, "Emotet"))
    assert c.verdict == Verdict.VERIFIED


def test_summarize():
    claims = [
        Claim(ClaimType.CVE, "CVE-2021-44228"),
        Claim(ClaimType.IOC_IP, "198.51.100.99"),
    ]
    V().verify_all(claims, REPORT)
    s = summarize(claims)
    assert s["total_claims"] == 2
    assert s["hallucination_rate"] == 0.5
