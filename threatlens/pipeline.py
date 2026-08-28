"""End-to-end pipeline: ingest -> extract -> verify -> persist JSONL."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from . import ingest
from .attack import AttackKB
from .extract import extract
from .llm import LLMClient
from .nvd import NVDClient
from .schema import Report
from .verify import Verifier, summarize

log = logging.getLogger(__name__)


def load_reports(source: str, limit: int) -> list[Report]:
    if source == "cisa":
        return ingest.fetch_cisa(limit=limit)
    if source == "otx":
        return ingest.fetch_otx(limit=limit)
    if source == "misp":
        from .ingest_misp import fetch_misp
        return fetch_misp("circl", limit=limit)
    raise ValueError(f"unknown source: {source}")


def _completed_keys(results_file: Path) -> set:
    """(model, report_id, run_index) triples already successfully done —
    lets long batch runs resume after rate-limit failures. Error records
    are NOT counted, so failed runs are retried."""
    done = set()
    if results_file.exists():
        with open(results_file, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if not rec.get("error"):
                    done.add((rec["model"], rec["report_id"],
                              rec.get("run_index", 0)))
    return done


def ingest_only(source: str, limit: int, out_dir: Path | str = "results") -> Path:
    """Fetch reports and merge into the corpus file (dedup by source_id).
    No LLM calls — build the corpus first, run models later."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    corpus_file = out / f"corpus_{source}.jsonl"
    existing = set()
    if corpus_file.exists():
        with open(corpus_file, encoding="utf-8") as f:
            existing = {json.loads(line)["source_id"] for line in f}
    reports = load_reports(source, limit)
    added = 0
    with open(corpus_file, "a", encoding="utf-8") as f:
        for r in reports:
            if r.source_id in existing:
                continue
            f.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
            added += 1
    log.info("Corpus %s: +%d new, %d already present, %d total",
             corpus_file, added, len(reports) - added, len(existing) + added)
    return corpus_file


def _process(reports, models, runs_per_report, out: Path,
             attack_bundle: str, delay: float = 2.0,
             resume: bool = True, max_new: int = 0) -> Path:
    kb = AttackKB(attack_bundle)
    verifier = Verifier(kb, NVDClient())
    results_file = out / "results.jsonl"
    done = _completed_keys(results_file) if resume else set()
    total = len(models) * len(reports) * runs_per_report
    remaining = total - len([1 for m in models for r in reports
                             for i in range(runs_per_report)
                             if (m, r.report_id, i) in done])
    log.info("Batch: %d combos total, %d already complete, %d remaining%s",
             total, total - remaining, remaining,
             f" (stopping after {max_new} this session)" if max_new else "")
    new_count = 0
    with open(results_file, "a", encoding="utf-8") as f:
        for model in models:
            client = LLMClient(model=model)
            for report in reports:
                for run_idx in range(runs_per_report):
                    if (model, report.report_id, run_idx) in done:
                        continue
                    if max_new and new_count >= max_new:
                        log.info("Session budget reached (%d new records); "
                                 "re-run the same command to continue.",
                                 max_new)
                        return results_file
                    new_count += 1
                    if delay:
                        time.sleep(delay)
                    res = extract(report, client, run_idx)
                    if not res.error:
                        verifier.verify_all(res.claims, report)
                    record = res.to_dict()
                    record["metrics"] = summarize(res.claims)
                    record["source"] = report.source
                    record["report_url"] = report.url
                    record["report_published"] = report.published
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    f.flush()
                    log.info("%s | %s | run %d | %s", model, report.source_id,
                             run_idx, record["metrics"])
    return results_file


def run(
    source: str = "cisa",
    limit: int = 5,
    models: list[str] | None = None,
    runs_per_report: int = 1,
    out_dir: Path | str = "results",
    attack_bundle: str = "data/enterprise-attack.json",
    delay: float = 2.0,
) -> Path:
    """Ingest live, then extract+verify. Returns results JSONL path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    models = models or ["llama3:8b"]
    reports = load_reports(source, limit)
    corpus_file = out / f"corpus_{source}.jsonl"
    with open(corpus_file, "w", encoding="utf-8") as f:
        for r in reports:
            f.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
    log.info("Saved %d reports to %s", len(reports), corpus_file)
    return _process(reports, models, runs_per_report, out, attack_bundle,
                    delay=delay)


def run_on_corpus(
    corpus_file: Path | str,
    models: list[str],
    runs_per_report: int = 1,
    out_dir: Path | str = "results",
    attack_bundle: str = "data/enterprise-attack.json",
    delay: float = 2.0,
    resume: bool = True,
    max_new: int = 0,
) -> Path:
    """Extract + verify over an existing corpus JSONL (skips ingestion)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports = []
    with open(corpus_file, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            reports.append(Report(source=d["source"], source_id=d["source_id"],
                                  title=d["title"], url=d["url"],
                                  published=d["published"], text=d["text"]))
    return _process(reports, models, runs_per_report, out, attack_bundle,
                    delay=delay, resume=resume, max_new=max_new)


def aggregate(results_file: Path | str = "results/results.jsonl") -> dict:
    """Per-model aggregate metrics across all runs.

    Dedups by (model, report_id, run_index), keeping the LAST record —
    early sessions predate resume support and left duplicates."""
    latest: dict = {}
    with open(results_file, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            latest[(rec["model"], rec["report_id"],
                    rec.get("run_index", 0))] = rec
    by_model: dict[str, dict] = {}
    for rec in latest.values():
        m = by_model.setdefault(rec["model"],
                                {"claims": 0, "verdicts": {}, "runs": 0,
                                 "errors": 0, "empty_runs": 0})
        m["runs"] += 1
        if rec.get("error"):
            m["errors"] += 1
            continue
        met = rec.get("metrics", {})
        n = met.get("total_claims", 0)
        if n == 0:
            # Silent failure: valid response, nothing extracted. Scores a
            # perfect hallucination rate while being useless — must be
            # reported alongside precision (audit finding, 2026-07-25).
            m["empty_runs"] += 1
        m["claims"] += n
        for k, v in (met.get("verdicts") or {}).items():
            m["verdicts"][k] = m["verdicts"].get(k, 0) + v
    for m in by_model.values():
        halluc = sum(m["verdicts"].get(k, 0)
                     for k in ("fabricated", "ungrounded", "mislabeled"))
        verifiable = m["claims"] - m["verdicts"].get("unverifiable", 0)
        m["hallucination_rate"] = (round(halluc / verifiable, 4)
                                   if verifiable else None)
        ok = m["runs"] - m["errors"]
        m["completion_rate"] = round(ok / m["runs"], 3) if m["runs"] else None
        m["empty_run_rate"] = round(m["empty_runs"] / ok, 3) if ok else None
        m["claims_per_run"] = round(m["claims"] / ok, 1) if ok else None
    return by_model
