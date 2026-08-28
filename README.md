# ThreatLens

**Claim-level grounding verification for LLM-extracted cyber threat intelligence.**

ThreatLens verifies every atomic claim an LLM extracts from a threat report — CVEs, indicators of compromise, ATT&CK techniques, threat actors, malware — against the authorities operational security already trusts: the NVD API, CVE.org CNA records, the MITRE ATT&CK STIX bundle, and the source document itself. Deterministic, at extraction time, with no human in the loop.

## Why not accuracy benchmarks?

Answer-key benchmarks score model output against static gold labels and report precision-style aggregates. ThreatLens reframes evaluation as *grounding*: each claim receives exactly one verdict —

| Verdict | Meaning |
|---|---|
| `VERIFIED` | Exists in an authority, grounded in the source, metadata consistent |
| `FABRICATED` | Does not exist in any authority and is absent from the source |
| `UNGROUNDED` | Real entity, but the source never states it (parametric-memory import) |
| `MISLABELED` | Real and grounded, but attached metadata is wrong |
| `UNVERIFIABLE` | No authority can adjudicate (fail-safe state, not a failure) |

The `UNGROUNDED`/`FABRICATED` split is the taxonomy's key contribution: a real CVE the source never mentions is not an invented fact, but it is equally unsafe in an automated pipeline.

## Key findings (paper §5)

Evaluation on **94 post-cutoff CISA advisories** (June–July 2026, 280 distinct CVEs) plus two MISP indicator-list events, across five open-weight models:

- **Hallucination is task-dependent, not model-intrinsic.** Nemotron-3-Super 120B: 0.00% [95% CI 0.00–0.52] on indicator copying vs 6.39% [4.65–8.73] on narrative advisories.
- **Precision metrics conceal silent failure.** Nemotron-3-nano 30B returned well-formed *empty* extractions on 100.0% [72.2–100.0] of CVE-bearing advisories; even the 120B model silently drops 11.2% [7.0–17.4].
- **Two reproducible failure modes at temperature 0:** parametric-memory CVE imports and systematic ATT&CK sub-technique confabulation.
- **Registry lag defeats existence checking.** After NIST's April 2026 NVD enrichment curtailment, 9 of 11 verbatim-quoted CVEs in same-week ICS advisories were absent from both NVD and CVE.org.

## The verifier audits itself

Every flagged claim was adjudicated by hand; five verifier false-positive classes were found, fixed, and pinned by regression tests (23 tests). Before these fixes the measured hallucination rate was 17.5%; after, 6.39% on identical data — the difference is entirely verifier error, which is why the audit trail ships as a first-class artifact.

## Repository layout

```
src/ or threatlens/     # Verifier, ingestion (CISA + MISP), provenance checks
scripts/
  wilson_intervals.py   # Wilson 95% score CIs for all reported rates
  silent_failure.py     # Yield / silent-failure breakdown per corpus
data/ (manifests)       # Corpus manifests with publication dates
verdicts/               # Per-claim verdict records (JSONL, resumable)
tests/                  # 23 regression tests pinning the verifier fixes
paper/main.tex          # Paper source
```

## Reproducing

1. `pip install -r requirements.txt`
2. Create a `.env` with your API key (`OPENROUTER_API_KEY=...`) — **never commit this file**.
3. Extraction: provider-agnostic client (local Ollama or any OpenAI-compatible endpoint), fixed prompt, temperature 0.
4. Verification: fully deterministic; results append to JSONL with resume support.
5. **Re-verification tool** recomputes every number in the paper from stored extractions under revised rules *without re-invoking any model* — verifier refinement is cheap and auditable.
6. `pytest` runs the regression suite.

Every table number regenerates from stored verdicts; no model calls required.

## Citation

```bibtex
@misc{threatlens2026,
  author = {Tusar, Shiddarth Dey},
  title  = {ThreatLens: Claim-Level Grounding Verification for LLM-Extracted Cyber Threat Intelligence},
  year   = {2026},
  howpublished = {\url{https://github.com/ShiddarthDey/threatlens}}
}
```

## Contact

Shiddarth Dey Tusar — Charles Sturt University, NSW, Australia — tusardey77@gmail.com
