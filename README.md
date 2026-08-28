# ThreatLens

LLM-powered cyber threat intelligence (CTI) extraction with **claim-level
hallucination verification** against authoritative sources: NVD, MITRE ATT&CK
STIX 2.1, and source-document provenance.

See `RESEARCH.md` for the verified literature review, gap analysis, hallucination
taxonomy, and the experimental design for the paper.

## What it does

```
real reports (CISA / OTX / MISP)
        │
        ▼
LLM extraction (Ollama: Llama 3 / Mistral / Qwen, or any OpenAI-compatible API)
   → atomic claims: CVEs, IoCs, ATT&CK techniques, actors, malware
        │
        ▼
Deterministic verifier → per-claim verdict:
   FABRICATED   entity doesn't exist (CVE not in NVD, invalid ATT&CK ID, ...)
   UNGROUNDED   real entity the source never mentions (parametric import)
   MISLABELED   real + grounded, but wrong metadata (ID↔name mismatch, ...)
   VERIFIED     exists + grounded + consistent
   UNVERIFIABLE authority unavailable (API down) — never guessed
        │
        ▼
results/results.jsonl + per-model hallucination metrics
```

## Quickstart

### 1. Installation

```bash
python -m venv .venv && .venv\Scripts\activate   # Windows (.venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
python scripts/download_attack.py                 # ATT&CK STIX bundle (~50 MB)
```

### 2. API Key Configuration

Copy `.env.example` to `.env` and add your API keys (all free tier):

```bash
copy .env.example .env                            # Windows (cp .env.example .env on Linux/macOS)
```

In `.env`, configure:
- `LLM_BASE_URL` & `LLM_API_KEY`: For hosted OpenAI-compatible APIs (OpenRouter, Groq, etc.). Default is local Ollama (`http://localhost:11434`), which requires no key.
- `OTX_API_KEY`: Free key from AlienVault OTX (required only for `--source otx`).
- `NVD_API_KEY`: Free NVD key to raise rate limits from 5 to 50 req/30s (optional).

### 3. Reproducing Paper Numbers Offline (No LLM / Network required)

To reproduce the paper's hallucination rates, silent failure rates, and Wilson 95% score confidence intervals directly from pre-produced extraction records:

```bash
# Run offline regression unit tests
python -m pytest tests/ -v

# Re-verify stored extractions & produce results/results_reverified.jsonl
python scripts/reverify.py

# Compute silent failure rates (CVE-bearing vs abstention)
python scripts/silent_failure.py results/results_reverified.jsonl

# Compute exact Wilson 95% confidence intervals for paper tables
python scripts/wilson_intervals.py

# Analyze per-model IoC recall & run-to-run consistency
python scripts/analyze.py
```

*Note: The stored evaluation file `results/results_reverified.jsonl` includes a `claude-fable-5/manual-demo` row, which was created during initial pipeline setup as a manual demonstration artifact and is not one of the five evaluated open-weight models.*

## Run Pipeline

```bash
# real pipeline: 5 CISA advisories, 1 model
python run.py pipeline --source cisa --limit 5 --models llama3:8b

# consistency experiment: 3 runs per report, 2 models
python run.py pipeline --source cisa --limit 20 --runs 3 --models llama3:8b mistral:7b

# build the corpus incrementally (no LLM calls; dedups by advisory ID —
# run every few days to accumulate ~100 post-cutoff reports)
python run.py ingest --source cisa --limit 100

# run models over a corpus; resumes automatically after rate-limit failures
python run.py corpus --corpus results/corpus_cisa.jsonl --models nvidia/nemotron-3-super-120b-a12b:free --runs 3 --delay 5

# aggregate results
python run.py aggregate
```

## Layout

```
threatlens/
  schema.py       data model, 5-way verdict taxonomy, IoC regexes, refang()
  ingest.py       CISA RSS + OTX pulses (real data only)
  ingest_misp.py  CIRCL / botvrij MISP OSINT feeds (license-clean corpus)
  llm.py          Ollama / OpenAI-compatible client (no LangChain — fewer deps)
  extract.py      structured extraction prompt + strict JSON parsing
  attack.py       ATT&CK KB: full STIX bundle, or compact fallback
  nvd.py          NVD API 2.0 client w/ disk cache + rate limiting
  verify.py       the hallucination detector (core contribution)
  pipeline.py     orchestration, JSONL persistence, aggregation
scripts/
  download_attack.py    full STIX bundle (~50 MB, preferred KB)
  build_compact_kb.py   fallback KB from PyPI attack-stix-lookup (v18.1)
  build_demo_corpus.py  reconstructs the demo corpus (see RUN_NOTES.md)
  run_offline.py        verify pre-produced extraction JSONs
  reverify.py           re-verify stored extractions offline
  silent_failure.py     compute silent-failure vs abstention metrics
  wilson_intervals.py   compute Wilson 95% CIs for paper tables
run.py            CLI
tests/test_verify.py
results/          stored evaluation corpus and extractions
```

## Design notes (honesty constraints)

- API failure ≠ non-existence: NVD outages yield `UNVERIFIABLE`, never `FABRICATED`.
- LLM/network errors are recorded in results, never silently dropped.
- IoCs must appear verbatim in the source (after defang normalization) — a model
  cannot legitimately "know" a hash the report doesn't state.
- Raw corpus is persisted alongside results for full reproducibility.
- The verifier only grounds verifiable claim types; narrative claims are out of
  scope and the paper must say so.
