"""Distinguish SILENT FAILURE from CORRECT ABSTENTION.

An empty extraction is only a failure if the source actually contained
extractable facts. This script splits empty runs by whether the source
report contains CVE IDs (regex ground truth).

Reported metric: silent_failure_rate = empty runs on CVE-bearing reports
                                       / successful runs.

  python scripts/silent_failure.py [results/results_reverified.jsonl]
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def print_table(stat: dict, title: str):
    print(f"\n=== {title} ===")
    print(f"{'model':<44} {'ok':>5} {'yield':>7} {'silent':>7} {'abstain':>8}")
    for model, s in sorted(stat.items(), key=lambda x: -x[1]["nonempty"]):
        ok = s["nonempty"] + s["silent"] + s["abstain"]
        if ok == 0:
            continue
        print(f"{model[:44]:<44} {ok:>5} "
              f"{s['nonempty']/ok:>6.1%} {s['silent']/ok:>6.1%} "
              f"{s['abstain']/ok:>7.1%}")


def main(results="results/results_reverified.jsonl",
         corpus_glob="results/corpus_*.jsonl"):
    corpus = {}
    for cf in Path("results").glob("corpus_*.jsonl"):
        for line in open(cf, encoding="utf-8"):
            d = json.loads(line)
            src_type = "cisa" if "cisa" in d["source"].lower() else "misp"
            corpus[d["report_id"]] = (src_type, len(set(CVE.findall(d["text"]))))

    latest = {}
    for line in open(results, encoding="utf-8"):
        r = json.loads(line)
        latest[(r["model"], r["report_id"], r.get("run_index", 0))] = r

    by_corpus = defaultdict(dict)
    pooled = defaultdict(lambda: {"nonempty": 0, "silent": 0, "abstain": 0})

    for (model, rid, _), r in latest.items():
        if r.get("error") or rid not in corpus:
            continue
        src_type, cve_cnt = corpus[rid]
        n = (r.get("metrics") or {}).get("total_claims", 0)
        has_cves = cve_cnt > 0
        cat = "nonempty" if n > 0 else ("silent" if has_cves else "abstain")

        s_corp = by_corpus[src_type].setdefault(model, {"nonempty": 0, "silent": 0, "abstain": 0})
        s_corp[cat] += 1
        pooled[model][cat] += 1

    for c_type in sorted(by_corpus.keys()):
        print_table(by_corpus[c_type], f"Corpus: {c_type.upper()}")

    print_table(pooled, "Pooled across all corpora")

    print("\nsilent  = empty extraction on a report that DOES contain CVEs "
          "(failure)\nabstain = empty extraction on a report with no CVEs "
          "(correct)")


if __name__ == "__main__":
    main(*sys.argv[1:])
