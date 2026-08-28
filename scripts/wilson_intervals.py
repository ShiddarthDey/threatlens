"""Compute Wilson 95% score intervals for ThreatLens paper rates.

Reads results/results_reverified.jsonl and corpus files to compute exact
binomial counts (k/n), percentages, and Wilson 95% CIs (z=1.96) for all
rates in Abstract, Table 1, and Table 2.
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """Return (proportion, ci_lower, ci_upper) as percentages (0..100)."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    denom = 1 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    half_width = (z * math.sqrt((p * (1 - p) / n) + (z**2) / (4 * n**2))) / denom
    lower = max(0.0, center - half_width) * 100
    upper = min(1.0, center + half_width) * 100
    return p * 100, lower, upper


def main():
    results_file = ROOT / "results" / "results_reverified.jsonl"

    # Load corpus info (report_id -> source_type, cve_count)
    corpus = {}
    for cf in (ROOT / "results").glob("corpus_*.jsonl"):
        for line in open(cf, encoding="utf-8"):
            d = json.loads(line)
            source = "cisa" if "cisa" in d["source"].lower() else "misp"
            corpus[d["report_id"]] = (source, len(set(CVE_RE.findall(d["text"]))))

    # Deduplicate results by (model, report_id, run_index), keeping latest
    latest = {}
    for line in open(results_file, encoding="utf-8"):
        r = json.loads(line)
        latest[(r["model"], r["report_id"], r.get("run_index", 0))] = r

    # Table 1: Grounding verdicts by (model, corpus)
    # k = fabricated + ungrounded + mislabeled claims
    # n = verifiable claims = total_claims - unverifiable claims
    t1_data = {}
    for (model, rid, _), r in latest.items():
        if r.get("error") or rid not in corpus:
            continue
        c_type = corpus[rid][0]
        key = (model, c_type)
        if key not in t1_data:
            t1_data[key] = {"runs": 0, "total_claims": 0, "verifiable_claims": 0, "hallucinated_claims": 0}
        
        t1_data[key]["runs"] += 1
        met = r.get("metrics") or {}
        verdicts = met.get("verdicts") or {}
        tot = met.get("total_claims", 0)
        unverif = verdicts.get("unverifiable", 0)
        halluc = verdicts.get("fabricated", 0) + verdicts.get("ungrounded", 0) + verdicts.get("mislabeled", 0)
        
        t1_data[key]["total_claims"] += tot
        t1_data[key]["verifiable_claims"] += (tot - unverif)
        t1_data[key]["hallucinated_claims"] += halluc

    print("=" * 80)
    print("TABLE 1: Grounding verdicts by model and corpus")
    print("=" * 80)
    print(f"{'Model':<42} {'Corpus':<6} {'Runs':>5} {'Claims':>7} {'Verif':>6} {'Halluc':>7} {'Rate (%)':>10} {'Wilson 95% CI':>20}")
    print("-" * 80)

    for (model, c_type), d in sorted(t1_data.items(), key=lambda x: (x[0][1], x[0][0])):
        k = d["hallucinated_claims"]
        n = d["verifiable_claims"]
        pct, lo, hi = wilson_ci(k, n)
        ci_str = f"[{lo:.2f}%, {hi:.2f}%]" if n > 0 else "N/A"
        rate_str = f"{pct:.2f}%" if n > 0 else "N/A"
        print(f"{model:<42} {c_type:<6} {d['runs']:>5} {d['total_claims']:>7} {n:>6} {k:>7} {rate_str:>10} {ci_str:>20}")

    # Table 2: Yield analysis over CVE-bearing advisories
    # Successful runs over CVE-bearing reports:
    # k_yield = nonempty runs
    # k_silent = empty runs on CVE-bearing reports
    # k_abstain = empty runs on non-CVE-bearing reports
    t2_data = {}
    for (model, rid, _), r in latest.items():
        if r.get("error") or rid not in corpus:
            continue
        c_type, cve_cnt = corpus[rid]
        if c_type != "cisa":  # Yield analysis is over CISA advisories
            continue
        if model not in t2_data:
            t2_data[model] = {"ok_runs": 0, "nonempty": 0, "silent": 0, "abstain": 0}
        
        t2_data[model]["ok_runs"] += 1
        tot_claims = (r.get("metrics") or {}).get("total_claims", 0)
        has_cves = cve_cnt > 0
        if tot_claims > 0:
            t2_data[model]["nonempty"] += 1
        else:
            if has_cves:
                t2_data[model]["silent"] += 1
            else:
                t2_data[model]["abstain"] += 1

    print("\n" + "=" * 80)
    print("TABLE 2: Yield & Silent Failure analysis over CISA advisories")
    print("=" * 80)
    print(f"{'Model':<42} {'OK Runs':>7} {'Yield % (CI)':>22} {'Silent % (CI)':>22} {'Abstain % (CI)':>22}")
    print("-" * 80)

    for model, d in sorted(t2_data.items(), key=lambda x: -x[1]["ok_runs"]):
        n = d["ok_runs"]
        y_p, y_l, y_h = wilson_ci(d["nonempty"], n)
        s_p, s_l, s_h = wilson_ci(d["silent"], n)
        a_p, a_l, a_h = wilson_ci(d["abstain"], n)
        y_str = f"{y_p:.1f}% [{y_l:.1f}%, {y_h:.1f}%]"
        s_str = f"{s_p:.1f}% [{s_l:.1f}%, {s_h:.1f}%]"
        a_str = f"{a_p:.1f}% [{a_l:.1f}%, {a_h:.1f}%]"
        print(f"{model:<42} {n:>7} {y_str:>22} {s_str:>22} {a_str:>22}")

    print("\n" + "=" * 80)
    print("ABSTRACT HEADLINE RATES WITH WILSON 95% CIs")
    print("=" * 80)
    # Nemotron-120B MISP hallucination: 0 / 739
    misp_120b = t1_data.get(("nvidia/nemotron-3-super-120b-a12b:free", "misp"))
    if misp_120b:
        p, l, h = wilson_ci(misp_120b["hallucinated_claims"], misp_120b["verifiable_claims"])
        print(f"Nemotron-120B MISP Hallucination: {p:.2f}% [{l:.2f}%, {h:.2f}%] (k={misp_120b['hallucinated_claims']}, n={misp_120b['verifiable_claims']})")
    
    # Nemotron-120B CISA hallucination: 36 / 563
    cisa_120b = t1_data.get(("nvidia/nemotron-3-super-120b-a12b:free", "cisa"))
    if cisa_120b:
        p, l, h = wilson_ci(cisa_120b["hallucinated_claims"], cisa_120b["verifiable_claims"])
        print(f"Nemotron-120B CISA Hallucination: {p:.2f}% [{l:.2f}%, {h:.2f}%] (k={cisa_120b['hallucinated_claims']}, n={cisa_120b['verifiable_claims']})")
    
    # Nemotron-120B Silent Failure: 16 / 143 (or 16 / 149)
    # Wait, let's check ok_runs for 120B on CISA:
    n120_t2 = t2_data.get("nvidia/nemotron-3-super-120b-a12b:free")
    if n120_t2:
        p, l, h = wilson_ci(n120_t2["silent"], n120_t2["ok_runs"])
        print(f"Nemotron-120B CISA Silent Failure: {p:.1f}% [{l:.1f}%, {h:.1f}%] (k={n120_t2['silent']}, n={n120_t2['ok_runs']})")


if __name__ == "__main__":
    main()
