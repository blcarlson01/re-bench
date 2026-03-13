"""fetch_ember.py — download and prepare the EMBER dataset.

Usage (full download, ~1.7 GB):
    python scripts/fetch_ember.py

Usage (quick synthetic sample for pipeline testing, no download):
    python scripts/fetch_ember.py --sample [N]

The script writes data/datasets/ember/ember.json as JSONL with one
{"sha256": "...", "label": 0|1} record per line, which is the format
consumed by tasks/ember_task.py.
"""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

import requests

EMBER_URLS = {
    "2017": "https://ember.elastic.co/ember_dataset.tar.bz2",
    "2017_2": "https://ember.elastic.co/ember_dataset_2017_2.tar.bz2",
    "2018_2": "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2",
}

OUT_DIR = Path("data/datasets/ember")
OUT_JSONL = OUT_DIR / "ember.json"


def download(url: str, out_path: Path) -> None:
    """Stream-download *url* to *out_path*, raising on HTTP errors."""
    print(f"Downloading {url} → {out_path}")
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    total = int(r.headers.get("Content-Length", 0))
    received = 0
    with open(out_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            f.write(chunk)
            received += len(chunk)
            if total:
                pct = received * 100 // total
                print(f"\r  {received // (1024*1024)} / {total // (1024*1024)} MB  ({pct}%)", end="", flush=True)
    print()


def extract_jsonl_from_tar(tar_path: Path, out_jsonl: Path, max_records: int = 0) -> int:
    """Extract sha256 + label records from a .tar.bz2 EMBER archive.

    Writes *out_jsonl* in JSONL format.  If *max_records* > 0 stops after
    that many records (useful for quick tests).  Returns record count.
    """
    written = 0
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with open(out_jsonl, "w", encoding="utf-8") as out_fh:
        with tarfile.open(tar_path, mode="r:bz2") as tf:
            for member in tf:
                if not (member.isfile() and member.name.endswith(".jsonl")):
                    continue
                raw = tf.extractfile(member)
                if raw is None:
                    continue
                print(f"  processing {member.name} …")
                for raw_line in raw:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if "sha256" not in obj or "label" not in obj:
                        continue
                    label = int(obj["label"])
                    if label not in (0, 1):      # skip unlabelled (-1)
                        continue
                    out_fh.write(json.dumps({"sha256": obj["sha256"], "label": label}) + "\n")
                    written += 1
                    if max_records and written >= max_records:
                        return written
    return written


def generate_sample_dataset(n: int = 60, out_jsonl: Path = OUT_JSONL) -> int:
    """Write *n* synthetic but realistic-looking records to *out_jsonl*.

    Half are labelled malware, half benign.  SHA256 values are deterministic
    hex digests so repeated runs are stable.
    """
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for i in range(n):
            sha = hashlib.sha256(f"ember_sample_{i}".encode()).hexdigest()
            label = i % 2          # alternating benign / malware
            f.write(json.dumps({"sha256": sha, "label": label}) + "\n")
            written += 1
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--sample",
        nargs="?",
        const=60,
        type=int,
        metavar="N",
        help="Generate N synthetic records instead of downloading (default 60).",
    )
    parser.add_argument(
        "--release",
        choices=list(EMBER_URLS),
        default="2018_2",
        help="Which EMBER release to download (default: 2018_2).",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=0,
        metavar="N",
        help="Stop after N records when processing the archive (0 = all).",
    )
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.sample is not None:
        n = generate_sample_dataset(n=args.sample)
        print(f"Wrote {n} synthetic records → {OUT_JSONL}")
        return

    # Full download path
    tar_path = OUT_DIR / f"ember_{args.release}.tar.bz2"
    download(EMBER_URLS[args.release], tar_path)
    n = extract_jsonl_from_tar(tar_path, OUT_JSONL, max_records=args.max_records)
    print(f"Wrote {n} records → {OUT_JSONL}")
    tar_path.unlink(missing_ok=True)   # remove archive to save disk space


if __name__ == "__main__":
    main()