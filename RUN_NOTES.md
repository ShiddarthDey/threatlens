# Silent-failure finding + n=94 corpus — 2026-07-25

Corpus now 94 CISA advisories. Attempted a within-family Nemotron size ladder
(9B / 30B / 120B). Result was unexpected and is itself a finding:

| Model | Runs ok | Empty runs | Claims | Halluc. rate |
|---|---|---|---|---|
| nemotron-3-super-120b | 149/186 | ~0 | 1,329 | **2.76%** |
| gpt-oss-20b | 40/186 | few | 155 | **16.55%** |
| nemotron-nano-9b-v2 | 5/30 | 1 | 7 | 0.00% |
| **nemotron-3-nano-30b-a3b** | **10/30** | **10 (100%)** | **0** | **n/a** |
| gemma-4-26b-a4b-it | 0/30 | — | — | n/a (all connection timeouts) |

**Adjudicated (2026-07-25, `scripts/silent_failure.py`):** empty extractions
were split by whether the source report actually contained CVE IDs, to
separate silent failure from correct abstention:

| Model | Successful runs | Yield | **Silent failure** | Correct abstention |
|---|---|---|---|---|
| nemotron-3-super-120b | 143 | 86.7% | **11.2%** (16 runs) | 2.1% (3) |
| gpt-oss-20b | 39 | 97.4% | 2.6% (1) | 0% |
| nemotron-nano-9b-v2 | 5 | 80.0% | 0% | 20% (1) |
| **nemotron-3-nano-30b** | **10** | **0%** | **100%** (10) | **0%** |

The 30B's empty runs were on advisories containing up to 7 CVEs each
(Naxclow IoT Platform, Brickcom Cameras, KEV alerts) — unambiguous silent
failure, not justified abstention. Even the best model (120B) silently
returns nothing on 11% of CVE-bearing advisories.

**Finding — silent failure / abstention collapse.** The 30B model returned
*valid, well-formed JSON with empty arrays on every single successful run*.
Under precision-only metrics (what every existing CTI benchmark reports) it
would score a perfect 0% hallucination rate while extracting literally nothing.
The 9B produced 7 claims across 4 non-empty runs — near-total abstention too.

This is the strongest argument yet for the paper's core methodological claim:
**hallucination rate alone is not a safety metric.** A CTI pipeline that
silently extracts nothing is as operationally dangerous as one that fabricates,
and only a recall/yield metric distinguishes them. `aggregate()` now reports
`empty_run_rate`, `claims_per_run` and `completion_rate` alongside the rate.

Reliability caveat for the paper: free-tier endpoints fail at very high rates
(305 dropped connections, ~120 429s across the study). Model *availability*
was the binding constraint on experiment design, not compute.

---

# Adjudicated results at n=65 advisories — 2026-07-08

After three audit rounds (grounded-malformed IoCs, registry lag, parent-prefix
labels, supply-chain product mismatch) and dedup of pre-resume duplicates,
verified with 23 passing regression tests:

| Model | Claims | Verified | Halluc. rate | Breakdown of hallucinations |
|---|---|---|---|---|
| Nemotron-3-Super 120B | 1,283 | 1,229 | **2.15%** | 11 mislabeled, 14 ungrounded, 2 fabricated (+27 unverifiable quarantined) |
| gpt-oss-20b | 155 | 125 | **10.07%** | 6 mislabeled, 7 ungrounded, 1 fabricated (+16 unverifiable) |
| Negative control | 8 | 1 | 87.5% | verifier discrimination intact after all rule changes |

Key phenomena in the residual (true) hallucinations:
- **Parametric-memory CVE imports**: on KEV-catalog alerts whose page text does
  not list the CVE IDs, models fill them in from memory (CVE-2026-10520 et al.,
  5/5 runs) — real CVEs, absent from source. The exact failure mode RESEARCH.md
  §2-G2 predicted, now observed in the wild.
- **Deterministic sub-technique confabulation** (T1071.001↔MQTT class errors).
- **~5× size effect**: 20B model hallucinates at 10% vs 120B at 2% on the same
  corpus with the same prompt.

Caveats that stand: recall metric is only meaningful on indicator-bearing
reports (ICS advisory regex GT is mostly reference URLs); gpt-oss n is small
(146/186 runs errored — flaky free endpoint); still need a third model family.

---

# Verifier audit findings — 2026-06-12 (final, adjudicated)

Every claim flagged on the CISA narrative run was manually adjudicated.
The breakdown rewrites the headline number — and produced three findings:

1. **Registry lag, quantified.** 9 of 11 CVEs cited verbatim in same-week
   CISA ICS advisories existed in *neither* NVD *nor* CVE.org
   (`not_in_nvd_or_cve_org`); the other 2 were registered and verified.
   These were verifier false positives, not model hallucinations — the model
   extracted source-attested IDs faithfully (`in_source: True` on all 9).
   Rule fixed: grounded-but-unregistered CVE → UNVERIFIABLE; only
   ungrounded+unregistered → FABRICATED. *Implication for automated defence:
   existence-checking against vulnerability registries fails on exactly the
   freshest (most operationally urgent) advisories.*

2. **Genuine confabulations: ATT&CK sub-technique pairing.** Nemotron-120B
   deterministically (temp 0, every run) paired real technique IDs with wrong
   sub-techniques: T1071.001 (Web Protocols) labeled "MQTT" (actually
   T1071.005), T1087.002 (Domain Account) labeled "Cloud Account Discovery"
   (actually T1087.004). Plausible, wrong, and systematic — the dangerous kind.

3. **Verifier false-positive sources found by audit:** (a) "Parent: Sub"
   label format penalized by name similarity (T1552.004 "Unsecured
   Credentials: Private Keys" is correct usage) — fixed, regression-tested;
   (b) the registry-lag rule above; (c) earlier: grounded-malformed IoC
   type confusion → MISLABELED. The audit loop (flag → adjudicate → fix →
   regression test) is itself the methodology the paper should report.

After fixes, estimated true hallucination content on the CISA corpus is
~4 mislabeled technique claims out of ~31 registry-verifiable claims
(~13%), concentrated entirely in sub-technique attribution. Re-run
`python scripts/reverify.py` for exact post-fix numbers without LLM calls.

---

# CISA narrative-advisory run — 2026-06-12 (later evening)

First run on real narrative reports: 3 fresh CISA ICS advisories
(icsa-26-162-01/-02/-03), Nemotron-3-Super 120B, 3 runs each, temp 0.

**Headline:** the same model that scored 0.0% hallucination on indicator-list
reports scored ~52% on narrative advisories (59 claims: 27 fabricated,
3 mislabeled, 1 ungrounded). Fabrication counts were *systematic* across runs
(2/2/2, 7/7/7) — deterministic confabulation, not sampling noise. This is the
core phenomenon the paper studies, observed cleanly on post-cutoff reports.

**Validity caveat (must resolve before citing):** these advisories are
days old; NVD has well-documented enrichment lag, so CVEs cited in fresh
advisories may be real but absent from NVD — the verifier would wrongly call
them FABRICATED. Fix applied: `nvd.py` now cross-checks CVE.org CNA records
(cveawg.mitre.org) before declaring non-existence, and empty descriptions
(RESERVED entries) no longer trigger MISLABELED. Stale negative cache entries
must be cleared and the run re-verified before the 52% figure is trusted.
The lesson itself is publishable: *existence verification needs multiple
authorities with different latencies.*

IoC recall findings (scripts/analyze.py, MISP corpus): Nemotron 120B
95–97% recall with ~100% run consistency; gpt-oss-20b 94% on the small report
but 2.8% on the 213-indicator report (truncation/recall collapse); Gemma-4-31B
95% on its one successful run. Precision-only metrics hide this entirely.

---

# Real-model results — 2026-06-12 (evening, OpenRouter free tier)

First genuine cross-model run over the 2-report MISP corpus, 3 runs/report,
temperature 0. Numbers from `results/aggregate.json` on the user's machine.

| Model | Successful runs | Claims | Hallucination rate | Notes |
|---|---|---|---|---|
| nvidia/nemotron-3-super-120b-a12b:free | 6/6 | 739 | 0.0 | Near-total IoC recall (~207/run on Dust Storm vs ~200 regex-extractable); run-to-run claim counts 39/39/39 and 208/207/207 — highly consistent |
| openai/gpt-oss-20b:free | 4/9 | 129 | 0.0078 | Partial recall (~15 IoCs/run on Turla); 1 type-confusion error (SHA1 line extracted as "ip" — motivated the grounded-malformed→MISLABELED taxonomy rule); JSON output needed strict=False + reasoning-field fallback |
| google/gemma-4-31b-it:free | 1/6 | 39 | 0.0 | Full Turla extraction on its one successful run; rest 429 |
| meta-llama 3.3-70B / 3.2-3B, qwen3-next-80b, qwen3-coder, hermes-3-405b | 0/30 | — | — | All route via the "Venice" free provider, saturated all day (HTTP 429 upstream, survives 3-retry backoff) |

**Interpretation (honest):** near-zero hallucination rates here are *expected*,
not impressive — this corpus is indicator-list-heavy, so extraction is a copy
task. The discriminative findings are (a) **recall variance**: 120B Nemotron
copies essentially everything, 20B gpt-oss extracts a fraction — precision
alone hides this, which is why `scripts/analyze.py` reports recall vs regex
ground truth; (b) the **type-confusion failure mode** caught in the wild;
(c) free-tier **provider routing determines model availability** — for the
paper, run Llama/Mistral/Qwen locally via Ollama or paid endpoints rather than
depending on saturated free pools. Narrative-heavy reports (CISA AAs, vendor
analyses) are where hallucination rates should separate models — that corpus
is the next milestone.

---

# End-to-end demo run — 2026-06-12

This documents exactly what was executed in Claude's sandboxed session, what is
real, and what the environment could not do. Read this before citing any number.

## What ran

1. **ATT&CK knowledge base.** The sandbox cannot reach raw.githubusercontent.com,
   so the full STIX bundle could not be downloaded here. Instead
   `scripts/build_compact_kb.py` built `data/attack_kb_compact.json` from the
   PyPI package `attack-stix-lookup` (data derived from the official
   `mitre-attack/attack-stix-data` bundle, **ATT&CK v18.1**, package built
   2026-02-16): 835 techniques, 580 actor aliases, 1,062 malware/tool names.
   On your machine, prefer `scripts/download_attack.py` (v19.1, May 2026).

2. **Corpus (real data).** CISA pages return empty to the sandbox fetcher
   (client-side rendering + bot protection) and OTX needs an API key, so the
   demo corpus uses two real TLP:WHITE events from the **CIRCL MISP OSINT feed**
   (license-clean, published for reuse), fetched live 2026-06-12:
   - `56bf4797-…` "OSINT - Turla - Harnessing SSL Certificates Using
     Infrastructure Chaining" (2016-02-13): 10 hostnames, 27 IPs, 1 X.509 SHA1,
     threat-actor Turla.
   - `56cdcbde-…` "OSINT Dust Storm Campaign Targeting Japanese Critical
     Infrastructure" (2016-02-23): 47 IPs, ~150 hostnames, campaign Dust Storm.
   Reconstruction script: `scripts/build_demo_corpus.py`. Corpus:
   `results/corpus_misp.jsonl`. A general MISP ingester was added at
   `threatlens/ingest_misp.py` for use on your machine.

3. **Extraction.** Ollama cannot run in the sandbox. The demo extraction was
   performed by **Claude itself acting as the extraction LLM** (model field:
   `claude-fable-5/manual-demo`), following `threatlens/extract.py`'s prompt.
   Files: `results/extractions/<report_id>.json`. This is a *pipeline
   demonstration*, not a benchmark result — paper numbers must come from the
   target open models (Llama 3, Mistral, Qwen) run via `run.py`.

4. **Verification.** `scripts/run_offline.py` ran the real verifier over the
   extractions against the ATT&CK KB and source provenance:
   - demo extraction: 37/37 claims VERIFIED, hallucination rate 0.0
   - **negative control** (`results/extractions_negative_control/`): a
     deliberately corrupted extraction, clearly labeled, to validate verifier
     discrimination. Result — every injected error class caught:

     | Injected error | Verdict |
     |---|---|
     | Real CVE-2021-44228, absent from source | UNGROUNDED |
     | Nonexistent CVE-2016-99999 (NVD unreachable in sandbox) | UNVERIFIABLE (fail-safe, not guessed) |
     | IP 198.51.100.99 not in source | UNGROUNDED |
     | Malformed IP 999.999.1.1 | FABRICATED |
     | Invalid technique T9999 | FABRICATED |
     | T1566.001 with wrong name "Process Injection" | MISLABELED |
     | Fictitious "Purple Walrus Group" | FABRICATED |
     | Genuine IoC from source | VERIFIED |

   Aggregate: `results/aggregate.json`. Full records: `results/results.jsonl`.

5. **NVD cache.** `data/nvd_cache/CVE-2021-44228.json` contains the **real**
   NVD API 2.0 response (fetched live 2026-06-12); the verifier used it for
   the ungrounded-CVE control. NVD is reachable from normal networks; the
   sandbox proxy blocks it, which exercised the UNVERIFIABLE fail-safe path.

## Honest limitations of this run

- Demo corpus is 2 reports from 2016 — fine for pipeline validation, useless
  for the paper's temporal-robustness claims. Build the real corpus (≥100
  post-cutoff reports) from CISA + OTX on your machine.
- Claude-as-extractor with the source IoCs listed explicitly is an easy
  setting; the 0.0 hallucination rate says nothing about Llama 3/Mistral on
  narrative-heavy reports. Do not cite it.
- The negative control validates the verifier's decision logic on injected
  errors; the paper additionally needs the human audit of verifier verdicts on
  *natural* model errors (RESEARCH.md §6, item 4).
- CISA ingestion (`threatlens/ingest.py`) could not be exercised here; test it
  on your machine — if cisa.gov blocks the default user agent, adjust `UA`.

## Reproduce on your machine

```bash
pip install -r requirements.txt
python scripts/download_attack.py          # full v19.1 STIX (preferred KB)
ollama pull llama3:8b                      # or set LLM_BASE_URL/LLM_API_KEY
python run.py pipeline --source cisa --limit 5 --models llama3:8b
# or, with extractions produced elsewhere:
python scripts/run_offline.py --model llama3:8b
```
