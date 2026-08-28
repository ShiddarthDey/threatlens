# ThreatLens Roadmap — what to do, when, and what to run

*Written 2026-06-12. Current state: pipeline validated end-to-end, 20/20 tests,
three adjudicated findings, ~5-report corpus, 2 reliably working models.*

---

## Publishability assessment (verified against live sources, 2026-06-12)

**The niche is still open.** No open-source, deterministic, claim-level CTI
verifier exists as of this check. Nearest neighbours and why they don't block you:
- GSAR (arXiv:2604.23366) — four-way grounding typology, but general
  multi-agent LLMs, no CTI authorities (NVD/ATT&CK), no security focus.
- KGV (arXiv:2408.08088) — CTI credibility via knowledge graphs, not
  claim-level registry grounding of LLM extractions.
- CyberThreat-Eval (Microsoft, 2026) — closest; proprietary workflow +
  expert annotators, not a released standalone verifier on open models.

**Your registry-lag finding just became very timely.** In April 2026 NIST
officially stopped universal NVD enrichment (only KEV / federal / EO-critical
CVEs get enriched now; 27,000+ CVEs unenriched; a June 2026 Inspector-General
report found NVD severity scores wrong 88% of the time). ThreatLens empirically
measured the downstream consequence: 9 of 11 CVEs in same-week CISA advisories
absent from both NVD and CVE.org, breaking naive existence-checking exactly
when it matters most. That connects your tool to a live, newsworthy crisis with
citable primary sources (NIST announcement, IG report).

**Honest risks:** corpus is still tiny (n=5 reports); only Nemotron-120B
thoroughly measured; the sub-technique-confabulation finding needs to replicate
across ≥3 models to be a claim rather than an anecdote.

**Realistic targets** (deadlines verified):
| Venue | Deadline | Fit |
|---|---|---|
| **AISec workshop @ ACM CCS 2026** | **July 24, 2026** | Primary target — 6 weeks; workshop-scale evaluation suffices |
| CAMLIS 2026 (Oct 21–23) | CFP deadline TBC (~July, watch camlis.org) | Strong fit, applied-ML-security audience |
| NDSS 2027 fall cycle | Aug 19, 2026 | Stretch goal — needs the full evaluation + human audit |
| ACSAC / RAID / DIMVA 2027 | next year's cycles | Fallback with mature artifact |

**Verdict: strong workshop-publishable chance by July 24 if Phases 1–3 below
are executed; conference-publishable with Phase 4.**

---

## Phase 1 — Corpus building (NOW → continuous, ~5 min every 2–3 days)

The single highest-value activity. Everything else scales with n.

**Every 2–3 days, run:**
```powershell
cd $HOME\Documents\ThreatLense
python run.py ingest --source cisa --limit 100
```
- Dedup is automatic; the corpus accumulates in `results/corpus_cisa.jsonl`.
- CISA's feed only exposes recent items — this is why it must be periodic.
- **Target: ≥50 advisories by July 1, ~100 by mid-July.**
- Optional: create a free OTX account, put the key in `.env` as
  `OTX_API_KEY=...`, then also run `python run.py ingest --source otx --limit 50`.

## Phase 2 — Model runs (whenever a new batch of reports exists, ~1–2 h each, resumable)

**After each ingest, run (safe to interrupt and re-run — it resumes):**
```powershell
python run.py corpus --corpus results/corpus_cisa.jsonl --models nvidia/nemotron-3-super-120b-a12b:free openai/gpt-oss-20b:free --runs 3 --delay 5
```
- Re-try the Venice-routed free models (meta-llama/llama-3.3-70b-instruct:free,
  qwen/qwen3-next-80b-a3b-instruct:free) at *different times of day* — their
  pools were saturated on 06-12. Morning UTC often works better.
- If they never free up: a few dollars of OpenRouter credit on the paid
  Llama-3.3-70B endpoint buys the whole evaluation; or install Ollama and run
  llama3:8b locally overnight. **The paper needs ≥3 model families.**
- **Target: 3–4 models × ~50 reports × 3 runs by mid-July.**

## Phase 3 — Analysis & paper draft (July 1 → July 24, AISec deadline)

**Weekly, after each batch:**
```powershell
python run.py aggregate          # headline numbers
python scripts\analyze.py        # recall + consistency (the hidden story)
```
**After ANY verifier rule change:** `python scripts\reverify.py` (no LLM cost),
then adjudicate every newly flagged claim by hand — that audit loop is your
methodology section. Log each adjudication in RUN_NOTES.md like we did.

**Paper structure (draft with me when n≥30):**
1. Intro: LLMs in CTI + the NVD crisis (cite NIST April 2026 announcement)
2. Related work: CTIBench, AthenaBench, 2503.23175, 2509.23573, CyberThreat-Eval, GSAR
3. ThreatLens: four-way taxonomy + dual-authority verification + audit loop
4. Results: (a) copy-task vs narrative-inference hallucination gap,
   (b) deterministic sub-technique confabulation, (c) recall collapse vs size,
   (d) registry lag quantified
5. Human audit: stratified 10% sample of verdicts, report verifier precision/recall
6. Limitations: verifiable claim types only; free-tier provider gating

## Phase 4 — Stretch (only if targeting NDSS Aug 19 / conferences)

- Human audit at scale (you + ideally one other annotator, Cohen's κ)
- Ablation: verification on/off → does filtering make small open models usable?
- RAG arm: give the model ATT&CK technique descriptions → does sub-technique
  confabulation drop?
- React dashboard (the original brief) — good for demo/artifact-evaluation, not
  needed for the paper's core.

## Weekly rhythm (summary)

| When | What | Command |
|---|---|---|
| Every 2–3 days | grow corpus | `python run.py ingest --source cisa --limit 100` |
| After each ingest | model runs (resumable) | `python run.py corpus --corpus results/corpus_cisa.jsonl --models ... --runs 3 --delay 5` |
| Weekly | numbers + analysis | `python run.py aggregate` + `python scripts\analyze.py` |
| After verifier changes | recompute + adjudicate | `python scripts\reverify.py` → update RUN_NOTES.md |
| ~July 1 | paper skeleton with Claude | bring results, draft sections |
| **July 24** | **AISec submission** | — |

## PhD angle

When emailing UNSW Canberra / Macquarie supervisors (do this in July, with
results in hand): lead with the working artifact + the registry-lag finding +
the audit methodology. A repo with tests, real data, and adjudicated findings
is worth more than any statement of purpose paragraph. Verify the current
scholarship listings before naming them in the email.
