"""Export the run history to CSV.

Usage:
  python scripts/export_results.py                       # all runs -> results/history.csv (scratch)
  python scripts/export_results.py --batch 20261124T231954  # -> results/history_<batch>.csv (kept in git)
"""

import argparse

from cyberloop import storage
from cyberloop.config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Export run history to CSV")
    parser.add_argument("--out", help="output path (default: a dated file when --batch is given)")
    parser.add_argument("--batch", help="only export this batch")
    args = parser.parse_args()

    out = args.out
    if out is None:
        out = f"results/history_{args.batch}.csv" if args.batch else "results/history.csv"

    conn = storage.connect(Settings().history_db)
    count = storage.export_csv(conn, out, batch=args.batch)
    print(f"exported {count} run(s) to {out}")


if __name__ == "__main__":
    main()
