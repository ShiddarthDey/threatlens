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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def main(results="results/results_reverified.jsonl",
         corpus_glob="results/corpus_*.jsonl"):
    corpus = {}
    for cf in Path(".").glob(corpus_glob.split("/")[-1]) or []:
        pass
    for cf in Path("results").glob("corpus_*.jsonl"):
        for line in open(cf, encoding="utf-8"):
            d = json.loads(line)
            corpus[d["report_id"]] = (d["title"][:44],
                                      len(set(CVE.findall(d["text"]))))

    latest = {}
    for line in open(results, encoding="utf-8"):
        r = json.loads(line)
        latest[(r["model"], r["report_id"], r.get("run_index", 0))] = r

    stat = {}
    for (model, rid, _), r in latest.items():
        if r.get("error") or rid not in corpus:
            continue
        n = (r.get("metrics") or {}).get("total_claims", 0)
        has_cves = corpus[rid][1] > 0
        s = stat.setdefault(model, {"nonempty": 0, "silent": 0, "abstain": 0})
        if n == 0:
            s["silent" if has_cves else "abstain"] += 1
        else:
            s["nonempty"] += 1

    print(f"{'model':<44} {'ok':>5} {'yield':>7} {'silent':>7} {'abstain':>8}")
    for model, s in sorted(stat.items(), key=lambda x: -x[1]["nonempty"]):
        ok = s["nonempty"] + s["silent"] + s["abstain"]
        print(f"{model[:44]:<44} {ok:>5} "
              f"{s['nonempty']/ok:>6.1%} {s['silent']/ok:>6.1%} "
              f"{s['abstain']/ok:>7.1%}")
    print("\nsilent  = empty extraction on a report that DOES contain CVEs "
          "(failure)\nabstain = empty extraction on a report with no CVEs "
          "(correct)")


if __name__ == "__main__":
    main(*sys.argv[1:])
