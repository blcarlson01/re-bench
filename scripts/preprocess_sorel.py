"""preprocess_sorel.py — prepare the SOREL-20M dataset from a local meta.db.

Usage (quick synthetic sample for pipeline testing, no network):
    python scripts/preprocess_sorel.py --sample [N]

Usage (process an already-downloaded meta.db):
    python scripts/preprocess_sorel.py --path data/datasets/sorel/meta.db [--sample N]

Both modes write data/datasets/sorel/sorel.jsonl in the unified JSONL format:
    {"id": ..., "dataset": "sorel", "artifact_type": "pe_metadata",
     "task": "behavior_tag_prediction", "input": ..., "answer": ...,
     "first_seen": ..., "time_period": ...}

which is consumed by tasks/sorel_task.py and data/sorel_loader.py.

To obtain meta.db, either run:
    python scripts/fetch_sorel.py --fetch    (downloads from S3, ~3.5 GB)

or copy it manually from:
    s3://sorel-20m/09-DEC-2020/processed-data/meta.db

⚠️  Agree to the SOREL Terms of Use before downloading:
    https://github.com/sophos/SOREL-20M/blob/master/Terms%20and%20Conditions%20of%20Use.pdf
"""

import argparse
import json
import sqlite3
from pathlib import Path

from scripts.fetch_sorel import (
    SOREL_TAGS,
    generate_sample_dataset,
    make_record,
)

OUTPUT = Path("data/datasets/sorel/sorel.jsonl")


# ---------------------------------------------------------------------------
# Local meta.db processing
# ---------------------------------------------------------------------------


def process_meta_db(db_path: Path, n: int, out_jsonl: Path = OUTPUT) -> int:
    """Read *n* tagged malware records from a local *db_path* and write sorel.jsonl.

    Selects only rows where ``label = 1`` (malware) and at least one behavioral
    tag column is non-zero.  The dominant tag (highest count) is used as the
    ground-truth answer.  Returns the number of records written.
    """
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    tag_cols = ", ".join(SOREL_TAGS)
    # Over-fetch to account for untagged malware rows (all-zero tag counts)
    query = (
        f"SELECT sha256, first_seen, {tag_cols} "
        f"FROM meta WHERE label = 1 LIMIT {n * 4}"
    )
    with sqlite3.connect(str(db_path)) as con:
        rows = con.execute(query).fetchall()

    written = 0
    with open(out_jsonl, "w", encoding="utf-8") as fh:
        for row in rows:
            if written >= n:
                break
            sha256 = row[0]
            first_seen = int(row[1]) if row[1] is not None else 0
            tag_counts = dict(zip(SOREL_TAGS, row[2:]))
            best_tag = max(tag_counts, key=lambda t: tag_counts[t])
            if tag_counts[best_tag] == 0:
                continue
            fh.write(json.dumps(make_record(sha256, best_tag, first_seen)) + "\n")
            written += 1
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--sample",
        nargs="?",
        const=60,
        type=int,
        metavar="N",
        help="Generate N synthetic records without reading meta.db (default 60).",
    )
    parser.add_argument(
        "--path",
        type=Path,
        metavar="DB_PATH",
        help="Path to an already-downloaded meta.db SQLite file.",
    )
    args = parser.parse_args()

    n = args.sample if args.sample is not None else 60

    if args.path is not None:
        if not args.path.exists():
            raise SystemExit(f"meta.db not found at '{args.path}'.  Run fetch_sorel.py --fetch first.")
        written = process_meta_db(args.path, n)
        print(f"Wrote {written} records from {args.path} → {OUTPUT}")
        return

    written = generate_sample_dataset(n=n)
    print(f"Wrote {written} synthetic records → {OUTPUT}")


if __name__ == "__main__":
    main()
