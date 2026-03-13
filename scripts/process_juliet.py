"""process_juliet.py — prepare the Juliet C/C++ Test Suite dataset.

Usage (quick synthetic sample for pipeline testing, no download):
    python scripts/process_juliet.py --sample [N]

Usage (download + process the real NIST Juliet v1.3 archive, ~220 MB):
    python scripts/process_juliet.py --download

Usage (process an already-extracted Juliet tree):
    python scripts/process_juliet.py

All modes write data/datasets/juliet/juliet.csv with columns:
    filename, source, cwe
which is the format consumed by tasks/juliet_task.py / data/juliet_loader.py.
"""

import argparse
import csv
import io
import os
import zipfile
from pathlib import Path

import requests

BASE = "data/datasets/juliet/"
OUTPUT = "data/datasets/juliet/juliet.csv"

JULIET_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
)

# ---------------------------------------------------------------------------
# Synthetic sample snippets keyed by CWE identifier
# ---------------------------------------------------------------------------
_SYNTHETIC_SNIPPETS: dict[str, str] = {
    "CWE-121": """\
#include <string.h>
/* CWE-121: Stack Based Buffer Overflow */
void bad() {
    char data[10];
    strcpy(data, "This string is too long for the buffer!");
}
""",
    "CWE-122": """\
#include <stdlib.h>
#include <string.h>
/* CWE-122: Heap Based Buffer Overflow */
void bad() {
    char *data = (char *)malloc(10);
    strcpy(data, "overflow_overflow_overflow");
    free(data);
}
""",
    "CWE-134": """\
#include <stdio.h>
/* CWE-134: Uncontrolled Format String */
void bad(char *data) {
    printf(data);  /* user-controlled format string */
}
""",
    "CWE-190": """\
#include <limits.h>
/* CWE-190: Integer Overflow or Wraparound */
void bad(int a, int b) {
    int result = a + b;  /* may overflow */
    if (result < 0) return;
}
""",
    "CWE-23": """\
#include <stdio.h>
/* CWE-23: Relative Path Traversal */
void bad(char *filename) {
    FILE *f = fopen(filename, "r");  /* unsanitised path */
    fclose(f);
}
""",
    "CWE-78": """\
#include <stdlib.h>
/* CWE-78: OS Command Injection */
void bad(char *cmd) {
    system(cmd);  /* command built from user input */
}
""",
    "CWE-89": """\
#include <stdio.h>
/* CWE-89: SQL Injection */
void bad(char *id) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE id = %s", id);
}
""",
    "CWE-457": """\
#include <stdio.h>
/* CWE-457: Use of Uninitialized Variable */
void bad() {
    int x;
    printf("%d\\n", x);  /* x is uninitialized */
}
""",
}


# ---------------------------------------------------------------------------
# Real on-disk processing
# ---------------------------------------------------------------------------

def find_files(base: str = BASE) -> list[str]:
    """Return all .c files under *base* recursively."""
    files = []
    for root, _, fs in os.walk(base):
        for file_name in fs:
            if file_name.endswith(".c"):
                files.append(os.path.join(root, file_name))
    return files


def extract_cwe_from_path(file_path: str) -> str:
    """Return the first path component that starts with 'CWE', else 'NONE'."""
    for part in file_path.split(os.sep):
        if part.startswith("CWE"):
            return part
    return "NONE"


def process_juliet(base: str = BASE, output: str = OUTPUT) -> int:
    """Walk *base* for .c files and write *output* CSV.  Returns record count."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["filename", "source", "cwe"])
        for file_path in find_files(base):
            try:
                with open(file_path, encoding="utf-8", errors="replace") as src:
                    code = src.read()
            except OSError:
                continue
            cwe = extract_cwe_from_path(file_path)
            writer.writerow([os.path.basename(file_path), code, cwe])
            written += 1
    return written


# ---------------------------------------------------------------------------
# Download mode
# ---------------------------------------------------------------------------

def download_and_process(output: str = OUTPUT) -> int:
    """Download the NIST Juliet v1.3 zip, extract .c files in-memory, write CSV."""
    print(f"Downloading Juliet test suite from {JULIET_URL} …")
    r = requests.get(JULIET_URL, stream=True, timeout=120)
    r.raise_for_status()
    total = int(r.headers.get("Content-Length", 0))
    received = 0
    buf = io.BytesIO()
    for chunk in r.iter_content(chunk_size=65536):
        buf.write(chunk)
        received += len(chunk)
        if total:
            print(f"\r  {received // (1024*1024)} / {total // (1024*1024)} MB  ({received*100//total}%)",
                  end="", flush=True)
    print()
    buf.seek(0)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    print("Extracting .c files …")
    with zipfile.ZipFile(buf) as zf:
        with open(output, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["filename", "source", "cwe"])
            for name in zf.namelist():
                if not name.endswith(".c"):
                    continue
                try:
                    code = zf.read(name).decode("utf-8", errors="replace")
                except Exception:
                    continue
                cwe = extract_cwe_from_path(name.replace("/", os.sep))
                writer.writerow([os.path.basename(name), code, cwe])
                written += 1
    return written


# ---------------------------------------------------------------------------
# Synthetic sample mode
# ---------------------------------------------------------------------------

def generate_sample_dataset(n: int = 40, output: str = OUTPUT) -> int:
    """Write *n* synthetic Juliet-style records to *output* CSV.

    Records cycle through the built-in CWE snippets so the dataset contains
    a realistic spread of vulnerability types.
    """
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    cwes = list(_SYNTHETIC_SNIPPETS.keys())
    written = 0
    with open(output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["filename", "source", "cwe"])
        for i in range(n):
            cwe = cwes[i % len(cwes)]
            fname = f"{cwe}_sample_{i:04d}.c"
            writer.writerow([fname, _SYNTHETIC_SNIPPETS[cwe], cwe])
            written += 1
    return written


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--sample",
        nargs="?",
        const=40,
        type=int,
        metavar="N",
        help="Generate N synthetic records instead of downloading (default 40).",
    )
    group.add_argument(
        "--download",
        action="store_true",
        help="Download the real NIST Juliet v1.3 archive and process it.",
    )
    parser.add_argument(
        "--output",
        default=OUTPUT,
        help=f"Path to write the output CSV (default: {OUTPUT}).",
    )
    parser.add_argument(
        "--base",
        default=BASE,
        help=f"Base directory to scan when processing on-disk files (default: {BASE}).",
    )
    args = parser.parse_args()

    if args.sample is not None:
        n = generate_sample_dataset(n=args.sample, output=args.output)
        print(f"Wrote {n} synthetic records → {args.output}")
    elif args.download:
        n = download_and_process(output=args.output)
        print(f"Wrote {n} records → {args.output}")
    else:
        n = process_juliet(base=args.base, output=args.output)
        print(f"Wrote {n} records → {args.output}")


if __name__ == "__main__":
    main()