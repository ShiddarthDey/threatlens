"""Run verification over pre-produced extraction JSONs (offline mode).

Useful when the LLM ran elsewhere: results/extractions/<report_id>.json
must match the extraction schema in threatlens/extract.py.

  python scripts/run_offline.py [--corpus results/corpus_misp.jsonl] [--model NAME]
"""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from threatlens.schema import Claim, ClaimType, ExtractionResult, Report
from threatlens.extract import _IOC_TYPE_MAP
from threatlens.attack import AttackKB
from threatlens.verify import Verifier, summarize
from threatlens.nvd import NVDClient


def claims_from_json(data: dict) -> list[Claim]:
    claims = []
    for c in data.get("cves") or []:
        claims.append(Claim(ClaimType.CVE, c["id"].upper().strip(),
                            label=c.get("product"), context=c.get("evidence")))
    for c in data.get("iocs") or []:
        ct = _IOC_TYPE_MAP.get(str(c.get("type", "")).lower())
        if ct:
            claims.append(Claim(ct, c["value"].strip(), context=c.get("evidence")))
    for c in data.get("attack_techniques") or []:
        claims.append(Claim(ClaimType.ATTACK_TECHNIQUE, c["id"].upper().strip(),
                            label=c.get("name"), context=c.get("evidence")))
    for c in data.get("threat_actors") or []:
        claims.append(Claim(ClaimType.THREAT_ACTOR, c["name"].strip(),
                            context=c.get("evidence")))
    for c in data.get("malware") or []:
        claims.append(Claim(ClaimType.MALWARE, c["name"].strip(),
                            context=c.get("evidence")))
    return claims


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="results/corpus_misp.jsonl")
    ap.add_argument("--extractions", default="results/extractions")
    ap.add_argument("--model", default="external")
    ap.add_argument("--out", default="results/results.jsonl")
    args = ap.parse_args()

    kb = AttackKB("data/enterprise-attack.json")
    verifier = Verifier(kb, NVDClient())

    reports = {}
    with open(args.corpus, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            r = Report(source=d["source"], source_id=d["source_id"],
                       title=d["title"], url=d["url"],
                       published=d["published"], text=d["text"])
            reports[r.report_id] = r

    with open(args.out, "a", encoding="utf-8") as out:
        for rid, report in reports.items():
            ext_file = Path(args.extractions) / f"{rid}.json"
            if not ext_file.exists():
                print(f"skip {rid}: no extraction file")
                continue
            data = json.loads(ext_file.read_text(encoding="utf-8"))
            res = ExtractionResult(rid, args.model, 0,
                                   claims=claims_from_json(data),
                                   summary=data.get("summary"))
            verifier.verify_all(res.claims, report)
            rec = res.to_dict()
            rec["metrics"] = summarize(res.claims)
            rec["source"] = report.source
            rec["report_url"] = report.url
            rec["report_published"] = report.published
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print(rid, report.title[:60], "->", rec["metrics"])


if __name__ == "__main__":
    main()
