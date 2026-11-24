"""Export the run history to CSV.

Usage:
  python scripts/export_results.py                       # all runs -> results/history.csv
  python scripts/export_results.py --batch 20261124T231954 --out results/batch.csv
"""

import argparse
from pathlib import Path

from cyberloop import storage
from cyberloop.config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Export run history to CSV")
    parser.add_argument("--out", default="results/history.csv")
    parser.add_argument("--batch", help="only export this batch")
    args = parser.parse_args()

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    conn = storage.connect(Settings().history_db)
    count = storage.export_csv(conn, args.out, batch=args.batch)
    print(f"exported {count} run(s) to {args.out}")


if __name__ == "__main__":
    main()
