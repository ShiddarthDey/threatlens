# ThreatLens

LLM-powered cyber threat intelligence (CTI) extraction with **claim-level
hallucination verification** against authoritative sources: NVD, MITRE ATT&CK
STIX 2.1, and source-document provenance.

See `RESEARCH.md` for the verified literature review, gap analysis, hallucination
taxonomy, and the experimental design for the paper.

## What it does

```
real reports (CISA / OTX)
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

## Setup

```bash
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
copy .env.example .env                            # fill in keys (all free)
python scripts/download_attack.py                 # ATT&CK STIX bundle (~50 MB)
```

LLM runtime — either:
- **Local**: install [Ollama](https://ollama.com), then `ollama pull llama3:8b` (needs ~8 GB RAM; `mistral:7b` similar). No key needed.
- **Hosted (no GPU)**: OpenRouter is preconfigured in `.env` (`LLM_BASE_URL` + `LLM_API_KEY`).
  Free open-weight model IDs confirmed available 2026-06-12:
  `deepseek/deepseek-v4-flash:free`, `moonshotai/kimi-k2.6:free`,
  `google/gemma-4-31b-it:free`, `nvidia/nemotron-3-super-120b-a12b:free`.
  Full current list: `curl https://openrouter.ai/api/v1/models` (look for `:free`),
  or use paid per-token IDs for Llama 3 / Mistral / Qwen exactly as named on openrouter.ai.

## Run

```bash
# offline unit tests (no network, no LLM)
pytest tests/ -v

# real pipeline: 5 CISA advisories, 1 model
python run.py pipeline --source cisa --limit 5 --models llama3:8b

# consistency experiment: 3 runs per report, 2 models
python run.py pipeline --source cisa --limit 20 --runs 3 --models llama3:8b mistral:7b

# build the corpus incrementally (no LLM calls; dedups by advisory ID —
# run every few days to accumulate ~100 post-cutoff reports)
python run.py ingest --source cisa --limit 100

# run models over a corpus; resumes automatically after rate-limit failures
python run.py corpus --corpus results/corpus_cisa.jsonl --models nvidia/nemotron-3-super-120b-a12b:free --runs 3 --delay 5

# aggregate / deep analysis / re-verify after verifier changes
python run.py aggregate
python scripts/analyze.py
python scripts/reverify.py
```

## Layout

```
threatlens/
  schema.py       data model, 4-way verdict taxonomy, IoC regexes, refang()
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
run.py            CLI
tests/test_verify.py
results/          demo run output — see RUN_NOTES.md before citing anything
```

A complete end-to-end demo run (real CIRCL MISP data, real verifier, labeled
negative control) is documented in **RUN_NOTES.md**.

## Design notes (honesty constraints)

- API failure ≠ non-existence: NVD outages yield `UNVERIFIABLE`, never `FABRICATED`.
- LLM/network errors are recorded in results, never silently dropped.
- IoCs must appear verbatim in the source (after defang normalization) — a model
  cannot legitimately "know" a hash the report doesn't state.
- Raw corpus is persisted alongside results for full reproducibility.
- The verifier only grounds verifiable claim types; narrative claims are out of
  scope and the paper must say so.
