# ThreatLens — Research Positioning & Gap Analysis

*Last updated: 2026-06-12. All citations verified against arXiv on this date.*

## 1. Verified related work

| Work | What it does | What it does NOT do |
|---|---|---|
| **CTIBench** (Alam et al., NeurIPS 2024 Spotlight, [arXiv:2406.07599](https://arxiv.org/abs/2406.07599)) | Static benchmark: CTI knowledge MCQs, CVE→CWE root cause, CVSS severity, ATT&CK technique extraction, actor attribution. 4,610 examples. | No claim-level hallucination verification; MCQ format unrealistic; static (leakage/drift over time). |
| **AthenaBench** (Alam, Bhusal, Rastogi et al., 2025, [arXiv:2511.01144](https://arxiv.org/abs/2511.01144)) | Extends CTIBench: dynamic dataset pipeline, dedup, refined metrics, risk-mitigation task. Finds open models trail far behind proprietary ones on reasoning-heavy CTI tasks. | Still benchmark-only — measures performance, does not *verify* outputs at extraction time. No grounding against NVD/STIX. |
| **"LLMs Are Unreliable for CTI"** (Mezzi, Massacci, Tuma, 2025, [arXiv:2503.23175](https://arxiv.org/abs/2503.23175), ESORICS) | Evaluation methodology quantifying consistency + confidence on 350 real reports. Shows LLMs are inconsistent and **overconfident** on real-size reports; few-shot/fine-tuning only partially help. | Diagnoses the problem; ships no open verification tool or mitigation pipeline. |
| **"Uncovering Vulnerabilities of LLM-Assisted CTI"** (2025, [arXiv:2509.23573](https://arxiv.org/abs/2509.23573)) | Empirical failure-mode taxonomy across CTI lifecycle: spurious metadata correlations, contradictory sources, constrained generalization to emerging threats. Causal interventions reduce failures. | Human-in-the-loop categorization framework, not an automated open-source verifier. |
| **CyberThreat-Eval / TRA** (Microsoft Research, 2026, [arXiv:2603.09452](https://arxiv.org/abs/2603.09452)) | Expert-annotated benchmark from a production CTI workflow (triage → deep search → drafting); analyst-centric metrics. Their TRA agent integrates "external ground truth" + expert feedback. **Closest competitor.** Explicitly notes LLMs "struggle to distinguish correct from incorrect information" and the "absence of external ground truth to verify technical details." | TRA is built around a proprietary corporate workflow and expert annotators; the *verification layer itself* is not released as a standalone, reproducible open tool; evaluates frontier proprietary models, not local open models a typical SOC can run. |
| **NIDS+LLM survey** (Feng & Sakurai, 2025, [arXiv:2510.23313](https://arxiv.org/abs/2510.23313)) | Survey of LLM integration in intrusion detection and its risks. ⚠️ *Note: this is a NIDS survey — the original project brief's framing of it as "CTI model drift" is loose. Cite it only for LLM-in-security-operations limitations, not for CTI drift claims.* | — |

## 2. The honest gap (corrected from the project brief)

The brief's claim "no open-source tool benchmarks LLM hallucination in CTI" is **too strong** as of mid-2026 — CyberThreat-Eval (Feb 2026) measures factual accuracy with expert annotation, and AthenaBench measures CTI task performance. The defensible, still-open gap is narrower and sharper:

**G1 — No open-source, deterministic, claim-level *grounding verifier* for LLM-extracted CTI.** Existing work measures hallucination via human experts (CyberThreat-Eval) or gold labels (CTIBench/AthenaBench). Nobody ships a tool that, at extraction time and with no human in the loop, cross-checks every atomic claim (CVE ID, IoC, ATT&CK technique ID+name pair, actor alias) against authoritative machine-readable sources: NVD API, ATT&CK STIX bundles, and the source document itself.

**G2 — Provenance vs. existence distinction.** A CVE can be *real* (exists in NVD) yet *hallucinated in context* (never mentioned in the source report — the model imported it from parametric memory). No published tool separates these two failure types. This taxonomy (fabricated / real-but-ungrounded / grounded-but-mislabeled / verified) is novel and directly actionable for SOC automation.

**G3 — Open local models under verification.** AthenaBench shows open models lag badly, but evaluates them with benchmark metrics only. Pairing cheap local models (Llama 3, Mistral via Ollama) with a deterministic verifier asks a different, practical question: *can verification close the reliability gap enough to make free local models usable for CTI?* That is the publishable experiment.

**G4 — Temporal robustness.** Static benchmarks decay (acknowledged by AthenaBench's "dynamic" pipeline). A live-fed pipeline (CISA/OTX) evaluated on reports published *after* model training cutoffs measures hallucination on genuinely unseen threats — addressing the "constrained generalization to emerging threats" failure mode identified in arXiv:2509.23573.

## 3. Paper claim (one sentence)

> We present ThreatLens, the first open-source pipeline that performs deterministic, claim-level grounding verification of LLM-extracted threat intelligence against NVD, MITRE ATT&CK STIX, and source-document provenance, and use it to quantify — across a four-way hallucination taxonomy — how far verification can close the reliability gap of free local LLMs on post-cutoff threat reports.

## 4. Hallucination taxonomy (core contribution)

For each atomic claim extracted by the LLM:

| Verdict | Definition | Check |
|---|---|---|
| **FABRICATED** | Entity does not exist in any authority | CVE not in NVD; ATT&CK ID not in STIX; IoC malformed |
| **UNGROUNDED** | Entity exists, but not present in / supported by the source document | Real CVE absent from source text (parametric-memory import); IoC not verbatim in source (after defang normalization) |
| **MISLABELED** | Entity exists and is grounded, but the LLM attached wrong metadata | ATT&CK ID paired with wrong technique name; CVE paired with wrong product |
| **VERIFIED** | Exists + grounded + metadata consistent | All checks pass |

Metrics: per-model hallucination rate by type, grounding precision/recall vs. regex-extractable IoCs, technique-mapping accuracy vs. ATT&CK STIX, consistency across runs (cf. arXiv:2503.23175's consistency metric).

## 5. Data sources (all verified live, 2026-06-12)

- **NVD API 2.0** — `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...` — free, no key required (key raises rate limit 5→50 req/30s). Tested: returns full JSON for CVE-2021-44228.
- **MITRE ATT&CK STIX 2.1** — `github.com/mitre-attack/attack-stix-data` — latest release v19.1 (May 2026). Download once, verify offline.
- **CISA Cybersecurity Advisories** — RSS/Atom feeds at cisa.gov + KEV catalog JSON (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`). Free, no key.
- **AlienVault OTX** — `otx.alienvault.com/api/v1/` — free but **requires API key** (free account). Pulses include community-validated IoCs usable as silver labels.

## 6. Experimental design (for the paper)

1. **Corpus**: ≥100 real advisories (CISA + OTX pulses + vendor blogs), all published **after** the evaluated models' training cutoffs. Record publication dates.
2. **Models**: Llama 3 8B/70B, Mistral 7B, Qwen 2.5 (Ollama); one proprietary API model as ceiling reference.
3. **Protocol**: 3 runs per report per model (consistency); fixed prompts; temperature 0 and 0.7 arms.
4. **Ground truth**: deterministic verifier output + stratified human audit of ~10% to validate the verifier itself (report verifier precision/recall — reviewers will demand this).
5. **Ablations**: verification on/off; RAG with ATT&CK descriptions on/off; effect of report length (cf. arXiv:2503.23175 finding on real-size reports).
6. **Outputs**: hallucination rates by taxonomy class × model × report recency; does verifier-filtered output reach usable precision for automated defence?

## 7. Venue targets

ACSAC, RAID, DIMVA (security); or NeurIPS/ACL dataset-and-benchmark tracks. Workshop fallback: CAMLIS, AISec (CCS workshop). PhD-fit framing: matches UNSW Canberra NLP-for-cyber-deception and Macquarie NLP-leakage topics (verify current scholarship listings before applying — not checked here).

## 8. Risks / honesty notes

- CyberThreat-Eval's TRA already "integrates external ground truth" — we must position against it explicitly (open tool vs. proprietary workflow; claim-level taxonomy vs. report-level accuracy; local models vs. frontier).
- The verifier can only ground *verifiable* claim types (CVE/IoC/ATT&CK/actor). Narrative claims (attribution reasoning, impact) stay unverifiable — scope the paper's claims accordingly.
- VirusTotal blog scraping (from the brief) has unclear ToS for redistribution — prefer CISA/OTX, which are explicitly open.
