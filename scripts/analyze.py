"""Deeper analysis of results.jsonl: per-model IoC recall vs regex ground
truth, run-to-run consistency, and claims-per-report breakdown.

Precision alone (hallucination rate) is not enough — a model that extracts
3 of 200 IoCs perfectly scores 0.0 but is operationally useless.

  python scripts/analyze.py
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from threatlens.schema import IOC_PATTERNS, refang  # noqa: E402


def regex_ground_truth(text: str) -> set[str]:
    """All regex-extractable IoC values in the source (refanged, lowered)."""
    src = refang(text)
    found = set()
    for pat in IOC_PATTERNS.values():
        for m in pat.finditer(src):
            found.add(m.group(0).lower())
    return found


def main(corpus="results/corpus_misp.jsonl", results="results/results.jsonl"):
    gt = {}
    titles = {}
    with open(corpus, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            gt[d["report_id"]] = regex_ground_truth(d["text"])
            titles[d["report_id"]] = d["title"][:48]

    # model -> report -> list of per-run claim-value sets
    runs = defaultdict(lambda: defaultdict(list))
    with open(results, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("error") or r["report_id"] not in gt:
                continue
            vals = {refang(c["value"]).lower() for c in r.get("claims", [])
                    if c["claim_type"].startswith("ioc")}
            runs[r["model"]][r["report_id"]].append(vals)

    print(f"{'model':<44} {'report':<20} {'runs':>4} {'gt':>4} "
          f"{'recall':>7} {'consist':>8}")
    for model, by_report in sorted(runs.items()):
        for rid, run_sets in by_report.items():
            truth = gt[rid]
            if not truth or not run_sets:
                continue
            recalls = [len(s & truth) / len(truth) for s in run_sets]
            avg_recall = sum(recalls) / len(recalls)
            # consistency: Jaccard of every run pair
            cons = 1.0
            if len(run_sets) > 1:
                pairs = [(a, b) for i, a in enumerate(run_sets)
                         for b in run_sets[i + 1:]]
                cons = sum(len(a & b) / len(a | b) if a | b else 1.0
                           for a, b in pairs) / len(pairs)
            print(f"{model:<44} {titles[rid]:<20.20} {len(run_sets):>4} "
                  f"{len(truth):>4} {avg_recall:>7.2%} {cons:>8.2%}")


if __name__ == "__main__":
    main(*sys.argv[1:])
