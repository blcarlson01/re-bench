"""fetch_bigvul.py — prepare the BigVul C/C++ vulnerability dataset.

Usage (quick synthetic sample for pipeline testing, no download):
    python scripts/fetch_bigvul.py --sample [N]

Usage (download the real BigVul dataset from GitHub, ~30 MB CSV):
    python scripts/fetch_bigvul.py --download

Both modes write data/datasets/bigvul/bigvul.csv with columns:
    id, func, cwe
which is the format consumed by tasks/bigvul_task.py / data/bigvul_loader.py.
"""

import argparse
import csv
import math
from pathlib import Path

import requests

OUTPUT = "data/datasets/bigvul/bigvul.csv"

# Real BigVul dataset from MSR 2020 — cleaned CSV (~180 K rows, ~30 MB).
# Source: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
BIGVUL_URL = (
    "https://raw.githubusercontent.com/ZeoVan/"
    "MSR_20_Code_vulnerability_CSV_Dataset/master/all_c_cpp_release2.0.csv"
)

# ---------------------------------------------------------------------------
# Synthetic sample snippets — realistic, varied vulnerable C functions
# ---------------------------------------------------------------------------
_SYNTHETIC_SNIPPETS: dict[str, str] = {
    "CWE-119": """\
#include <string.h>
/* CWE-119: Improper Restriction of Operations within Bounds of a Memory Buffer */
void copy_data(char *src) {
    char buf[64];
    strcpy(buf, src);   /* no length check — destination may overflow */
}
""",
    "CWE-120": """\
#include <stdio.h>
#include <string.h>
/* CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') */
void process_input(char *input) {
    char local[128];
    gets(local);        /* inherently unsafe — no length limit */
}
""",
    "CWE-121": """\
#include <string.h>
/* CWE-121: Stack-Based Buffer Overflow */
void bad() {
    char data[10];
    strcpy(data, "This string is far too long for the buffer allocated above!");
}
""",
    "CWE-122": """\
#include <stdlib.h>
#include <string.h>
/* CWE-122: Heap-Based Buffer Overflow */
void bad() {
    char *data = (char *)malloc(10);
    if (data == NULL) return;
    strcpy(data, "overflow_content_exceeds_allocation");
    free(data);
}
""",
    "CWE-125": """\
#include <stdlib.h>
/* CWE-125: Out-of-bounds Read */
int read_element(int *arr, int idx, int size) {
    return arr[idx];    /* idx not validated against size */
}
""",
    "CWE-134": """\
#include <stdio.h>
/* CWE-134: Uncontrolled Format String */
void log_message(char *user_input) {
    printf(user_input); /* user-supplied format string — allows %n writes */
}
""",
    "CWE-190": """\
#include <limits.h>
#include <stdlib.h>
/* CWE-190: Integer Overflow or Wraparound */
void allocate_buffer(unsigned int count, unsigned int size) {
    unsigned int total = count * size;  /* may wrap around to a small value */
    char *buf = (char *)malloc(total);
    free(buf);
}
""",
    "CWE-191": """\
#include <stdint.h>
/* CWE-191: Integer Underflow (Wrap or Wraparound) */
uint32_t subtract_unsigned(uint32_t a, uint32_t b) {
    return a - b;   /* if b > a this wraps to a large positive number */
}
""",
    "CWE-22": """\
#include <stdio.h>
/* CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) */
void open_file(const char *filename) {
    char path[256];
    snprintf(path, sizeof(path), "/var/data/%s", filename); /* no traversal check */
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}
""",
    "CWE-23": """\
#include <stdio.h>
/* CWE-23: Relative Path Traversal */
void serve_file(char *name) {
    FILE *f = fopen(name, "r");   /* relative path, no sanitisation */
    if (f) fclose(f);
}
""",
    "CWE-36": """\
#include <stdio.h>
/* CWE-36: Absolute Path Traversal */
void write_output(char *dest) {
    FILE *f = fopen(dest, "w");   /* absolute path supplied by caller */
    if (f) fclose(f);
}
""",
    "CWE-369": """\
#include <stdio.h>
/* CWE-369: Divide By Zero */
int compute_ratio(int a, int b) {
    return a / b;   /* b may be zero */
}
""",
    "CWE-401": """\
#include <stdlib.h>
/* CWE-401: Missing Release of Memory after Effective Lifetime (Memory Leak) */
void process_items(int n) {
    int *arr = (int *)malloc(n * sizeof(int));
    if (n < 0) return;  /* leak: arr not freed before early return */
    free(arr);
}
""",
    "CWE-415": """\
#include <stdlib.h>
/* CWE-415: Double Free */
void bad(int *p) {
    free(p);
    free(p);    /* second free on same pointer — undefined behaviour */
}
""",
    "CWE-416": """\
#include <stdlib.h>
#include <stdio.h>
/* CWE-416: Use After Free */
void bad() {
    char *buf = (char *)malloc(32);
    free(buf);
    printf("%s\n", buf);    /* buf accessed after being freed */
}
""",
    "CWE-457": """\
#include <stdio.h>
/* CWE-457: Use of Uninitialized Variable */
void bad() {
    int x;
    printf("%d\n", x);  /* x is read before any assignment */
}
""",
    "CWE-476": """\
#include <stdio.h>
#include <string.h>
/* CWE-476: NULL Pointer Dereference */
void bad(char *p) {
    int len = strlen(p);    /* p may be NULL */
    printf("len=%d\n", len);
}
""",
    "CWE-78": """\
#include <stdlib.h>
/* CWE-78: Improper Neutralization of Special Elements used in an OS Command
   ('OS Command Injection') */
void run_command(char *cmd) {
    system(cmd);    /* cmd constructed from user-supplied data */
}
""",
    "CWE-89": """\
#include <stdio.h>
/* CWE-89: SQL Injection */
void query_user(char *id) {
    char sql[256];
    sprintf(sql, "SELECT * FROM users WHERE id = '%s'", id); /* unsanitised */
}
""",
    "CWE-90": """\
#include <stdio.h>
/* CWE-90: LDAP Injection */
void ldap_search(char *user) {
    char filter[256];
    sprintf(filter, "(uid=%s)", user);  /* user input not escaped for LDAP */
}
""",
}


# ---------------------------------------------------------------------------
# Synthetic dataset generation
# ---------------------------------------------------------------------------

def generate_sample_dataset(n: int, output: str = OUTPUT) -> int:
    """Write *n* synthetic BigVul-format rows to *output*.

    Rows cycle over *_SYNTHETIC_SNIPPETS*, repeating as needed.  Returns the
    number of rows written.
    """
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    keys = list(_SYNTHETIC_SNIPPETS.keys())
    k = len(keys)
    written = 0
    with open(output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "func", "cwe"])
        writer.writeheader()
        for i in range(n):
            cwe = keys[i % k]
            func = _SYNTHETIC_SNIPPETS[cwe]
            # Cycle copies so every CWE appears ≥ ceil(n/k) times
            if i >= k:
                variant = i // k
                func = func.rstrip("\n") + f"\n/* instance {variant} */\n"
            writer.writerow({"id": i + 1, "func": func, "cwe": cwe})
            written += 1
    return written


# ---------------------------------------------------------------------------
# Download — real BigVul dataset
# ---------------------------------------------------------------------------

def download_bigvul(output: str = OUTPUT) -> int:
    """Stream the real BigVul CSV from GitHub and reformat to id/func/cwe.

    The upstream CSV has columns ``Unnamed: 0``, ``func``, ``cwe_id`` among
    others.  We extract only those three and rename them.  Returns row count.
    """
    import csv as _csv
    import io

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading BigVul dataset from {BIGVUL_URL} …")
    with requests.get(BIGVUL_URL, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunks = []
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                chunks.append(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r  {pct}% ({downloaded}/{total} bytes)", end="", flush=True)
        print()
        raw = b"".join(chunks).decode("utf-8", errors="replace")

    reader = _csv.DictReader(io.StringIO(raw))
    written = 0
    with open(output, "w", newline="", encoding="utf-8") as fh:
        writer = _csv.DictWriter(fh, fieldnames=["id", "func", "cwe"])
        writer.writeheader()
        for row in reader:
            func = row.get("func", "").strip()
            cwe = row.get("cwe_id", row.get("CWE ID", "")).strip()
            idx = row.get("Unnamed: 0", row.get("", written))
            if not func or not cwe:
                continue
            writer.writerow({"id": idx, "func": func, "cwe": cwe})
            written += 1
    return written


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--sample",
        metavar="N",
        type=int,
        nargs="?",
        const=40,
        help="generate N synthetic rows (default 40) without network access",
    )
    mode.add_argument(
        "--download",
        action="store_true",
        help="download the real BigVul dataset from GitHub (~30 MB)",
    )
    p.add_argument(
        "--output",
        default=OUTPUT,
        help=f"destination CSV path (default: {OUTPUT})",
    )
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    if args.download:
        count = download_bigvul(args.output)
        print(f"Wrote {count} rows to {args.output}")
    else:
        n = args.sample if args.sample is not None else 40
        count = generate_sample_dataset(n, args.output)
        print(f"Wrote {count} synthetic rows to {args.output}")
