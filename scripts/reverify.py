"""Re-run verification over claims already stored in results.jsonl
(no LLM calls). Use after verifier rule changes.

Writes results/results_reverified.jsonl and prints the new aggregate.

  python scripts/reverify.py
"""
import json
import sys
from glob import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from threatlens.attack import AttackKB
from threatlens.nvd import NVDClient
from threatlens.pipeline import aggregate
from threatlens.schema import Claim, ClaimType, Report
from threatlens.verify import Verifier, summarize


def main(results_in="results/results.jsonl",
         results_out="results/results_reverified.jsonl"):
    reports = {}
    for cf in glob("results/corpus_*.jsonl"):
        with open(cf, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line)
                r = Report(source=d["source"], source_id=d["source_id"],
                           title=d["title"], url=d["url"],
                           published=d["published"], text=d["text"])
                reports[r.report_id] = r

    verifier = Verifier(AttackKB("data/enterprise-attack.json"), NVDClient())

    n_in, n_out = 0, 0
    with open(results_in, encoding="utf-8") as fin, \
         open(results_out, "w", encoding="utf-8") as fout:
        for line in fin:
            rec = json.loads(line)
            n_in += 1
            report = reports.get(rec["report_id"])
            if rec.get("error") or report is None:
                fout.write(line)
                n_out += 1
                continue
            claims = [Claim(ClaimType(c["claim_type"]), c["value"],
                            label=c.get("label"), context=c.get("context"))
                      for c in rec.get("claims") or []]
            verifier.verify_all(claims, report)
            rec["claims"] = [c.to_dict() for c in claims]
            rec["metrics"] = summarize(claims)
            rec["reverified"] = True
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n_out += 1

    print(f"re-verified {n_out}/{n_in} records -> {results_out}\n")
    print(json.dumps(aggregate(results_out), indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:])
