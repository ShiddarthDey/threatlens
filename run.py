"""ThreatLens CLI.

Examples:
  python run.py pipeline --source cisa --limit 5 --models llama3:8b mistral:7b
  python run.py corpus --models deepseek/deepseek-v4-flash:free --runs 3
  python run.py aggregate
"""
import argparse
import json
import logging

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from threatlens import pipeline

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main():
    ap = argparse.ArgumentParser(prog="threatlens")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pipeline", help="ingest -> extract -> verify")
    p.add_argument("--source", choices=["cisa", "otx", "misp"], default="cisa")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--models", nargs="+", default=["llama3:8b"])
    p.add_argument("--runs", type=int, default=1,
                   help="runs per report (consistency measurement)")
    p.add_argument("--out", default="results")
    p.add_argument("--delay", type=float, default=2.0,
                   help="seconds between LLM calls (free-tier friendliness)")

    g = sub.add_parser("ingest", help="fetch reports into corpus only (no LLM)")
    g.add_argument("--source", choices=["cisa", "otx", "misp"], default="cisa")
    g.add_argument("--limit", type=int, default=100)
    g.add_argument("--out", default="results")

    c = sub.add_parser("corpus", help="extract+verify over an existing corpus JSONL")
    c.add_argument("--corpus", default="results/corpus_misp.jsonl")
    c.add_argument("--models", nargs="+", required=True)
    c.add_argument("--runs", type=int, default=1)
    c.add_argument("--out", default="results")
    c.add_argument("--delay", type=float, default=2.0,
                   help="seconds between LLM calls (free-tier friendliness)")
    c.add_argument("--no-resume", action="store_true",
                   help="re-run combos even if already completed")
    c.add_argument("--max-new", type=int, default=0,
                   help="stop after N new records this session (0 = no limit); "
                        "re-run the same command later to continue")

    sub.add_parser("aggregate", help="summarize results.jsonl per model")

    args = ap.parse_args()
    if args.cmd == "pipeline":
        f = pipeline.run(source=args.source, limit=args.limit,
                         models=args.models, runs_per_report=args.runs,
                         out_dir=args.out, delay=args.delay)
        print(f"\nResults written to {f}")
        print(json.dumps(pipeline.aggregate(f), indent=2))
    elif args.cmd == "ingest":
        f = pipeline.ingest_only(source=args.source, limit=args.limit,
                                 out_dir=args.out)
        print(f"\nCorpus updated: {f}")
    elif args.cmd == "corpus":
        f = pipeline.run_on_corpus(corpus_file=args.corpus, models=args.models,
                                   runs_per_report=args.runs, out_dir=args.out,
                                   delay=args.delay,
                                   resume=not args.no_resume,
                                   max_new=args.max_new)
        print(f"\nResults written to {f}")
        print(json.dumps(pipeline.aggregate(f), indent=2))
    elif args.cmd == "aggregate":
        print(json.dumps(pipeline.aggregate(), indent=2))


if __name__ == "__main__":
    main()
