"""fetch_sorel.py — prepare the SOREL-20M dataset for RE-Bench.

⚠️  Terms of Use: You must agree to the Sophos / ReversingLabs Terms and
Conditions of Use before downloading any SOREL data.  Read them at:
  https://github.com/sophos/SOREL-20M/blob/master/Terms%20and%20Conditions%20of%20Use.pdf

Usage (quick synthetic sample — no download required):
    python scripts/fetch_sorel.py --sample [N]

Usage (download meta.db from S3, requires AWS CLI and ~3.5 GB free disk space):
    python scripts/fetch_sorel.py --fetch [--sample N]

The --sample flag (default 60) controls how many JSONL records are written.
When --fetch is given, real sha256 hashes and timestamps from meta.db are used;
otherwise fully synthetic records are generated.

Both modes write data/datasets/sorel/sorel.jsonl in the unified JSONL format:
    {"id": ..., "dataset": "sorel", "artifact_type": "pe_metadata",
     "task": "behavior_tag_prediction", "input": ..., "answer": ...,
     "first_seen": ..., "time_period": ...}

The ``time_period`` field (e.g. "2019-H2") is derived from ``first_seen`` and
enables temporal drift analysis in analysis/run_analysis.py — accuracy is
broken down per half-year cohort to detect model degradation on newer samples.
"""

import argparse
import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path

OUT_DIR = Path("data/datasets/sorel")
OUT_JSONL = OUT_DIR / "sorel.jsonl"
META_DB = OUT_DIR / "meta.db"

_S3_META_DB = "s3://sorel-20m/09-DEC-2020/processed-data/meta.db"

# Behavioral tags present in the SOREL meta.db tag columns
SOREL_TAGS: list[str] = [
    "ransomware",
    "trojan",
    "backdoor",
    "downloader",
    "loader",
    "worm",
    "coinminer",
    "virus",
]

# SOREL dataset spans roughly 2018-01-01 through 2020-12-09
_TIME_PERIODS: list[tuple[str, int, int]] = [
    ("2018-H1", 1514764800, 1530316800),
    ("2018-H2", 1530316800, 1546300800),
    ("2019-H1", 1546300800, 1561852800),
    ("2019-H2", 1561852800, 1577836800),
    ("2020-H1", 1577836800, 1593561600),
    ("2020-H2", 1593561600, 1609372800),
]

# Representative PE imports keyed by behavioral tag (used for both synthetic
# generation and as templates when the real pe_metadata LMDB is not available)
_TAG_IMPORTS: dict[str, dict[str, list[str]]] = {
    "ransomware": {
        "KERNEL32.dll": [
            "CreateFileW",
            "WriteFile",
            "FindFirstFileW",
            "FindNextFileW",
            "DeleteFileW",
        ],
        "ADVAPI32.dll": [
            "CryptAcquireContextA",
            "CryptEncrypt",
            "CryptGenKey",
            "CryptDestroyKey",
        ],
    },
    "trojan": {
        "KERNEL32.dll": [
            "CreateProcessW",
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
        ],
        "WS2_32.dll": ["socket", "connect", "send", "recv"],
    },
    "backdoor": {
        "WS2_32.dll": ["WSAStartup", "socket", "bind", "listen", "accept"],
        "KERNEL32.dll": ["CreatePipe", "CreateProcessW", "ReadFile", "WriteFile"],
    },
    "downloader": {
        "WINHTTP.dll": [
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "WinHttpReadData",
        ],
        "KERNEL32.dll": ["CreateFileW", "WriteFile"],
    },
    "loader": {
        "KERNEL32.dll": [
            "LoadLibraryA",
            "GetProcAddress",
            "VirtualAlloc",
            "VirtualProtect",
        ],
        "NTDLL.dll": [
            "NtUnmapViewOfSection",
            "NtWriteVirtualMemory",
            "NtResumeThread",
        ],
    },
    "worm": {
        "KERNEL32.dll": [
            "CopyFileW",
            "GetDriveTypeW",
            "FindFirstFileW",
            "FindNextFileW",
        ],
        "WS2_32.dll": ["socket", "connect", "send"],
    },
    "coinminer": {
        "KERNEL32.dll": ["CreateThread", "SetThreadPriority", "VirtualAlloc"],
        "WS2_32.dll": ["socket", "connect", "send", "recv"],
    },
    "virus": {
        "KERNEL32.dll": [
            "OpenFile",
            "ReadFile",
            "WriteFile",
            "FindFirstFileA",
            "FindNextFileA",
        ],
        "ADVAPI32.dll": ["AdjustTokenPrivileges", "OpenProcessToken"],
    },
}

_TAG_STRINGS: dict[str, list[str]] = {
    "ransomware": [
        "YOUR FILES HAVE BEEN ENCRYPTED",
        ".onion",
        "bitcoin",
        "README_DECRYPT.txt",
    ],
    "trojan": ["cmd.exe", "powershell.exe", "http://", "User-Agent"],
    "backdoor": ["shell", "reverse", "0.0.0.0", "bind"],
    "downloader": ["http://", "https://", "URLDownloadToFile", "User-Agent: Mozilla"],
    "loader": ["shellcode", "reflective", "LoadLibrary", "VirtualAlloc"],
    "worm": ["AUTORUN.INF", "autorun.inf", "removable", "USB"],
    "coinminer": ["stratum+tcp://", "xmrig", "mining pool", "wallet"],
    "virus": ["INFECTED", "infect", ".exe", "AppendFile"],
}

_TAG_SECTIONS: dict[str, list[str]] = {
    "ransomware": [".text", ".rdata", ".data", ".rsrc"],
    "trojan": [".text", ".data", ".pdata", ".reloc"],
    "backdoor": [".text", ".data", ".rsrc"],
    "downloader": [".text", ".rdata", ".data"],
    "loader": [".text", ".data", "UPX0", "UPX1"],
    "worm": [".text", ".data", ".rsrc", ".reloc"],
    "coinminer": [".text", ".data", ".bss"],
    "virus": [".text", ".data", ".virus"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def assign_time_period(first_seen: int) -> str:
    """Return the half-year label for a UNIX timestamp, or 'unknown'."""
    for name, start, end in _TIME_PERIODS:
        if start <= first_seen < end:
            return name
    return "unknown"


def format_pe_input(
    imports: dict[str, list[str]],
    sections: list[str],
    strings: list[str],
) -> str:
    """Return a human-readable PE metadata block suitable as an LLM prompt input."""
    import_lines = [f"  {dll}: {', '.join(fns)}" for dll, fns in imports.items()]
    return (
        "PE Imports:\n"
        + "\n".join(import_lines)
        + "\nSection Names: "
        + ", ".join(sections)
        + "\nStrings: "
        + ", ".join(strings[:8])
    )


def make_record(sha256: str, tag: str, first_seen: int) -> dict:
    """Build a single SOREL JSONL record."""
    return {
        "id": sha256,
        "dataset": "sorel",
        "artifact_type": "pe_metadata",
        "task": "behavior_tag_prediction",
        "input": format_pe_input(
            _TAG_IMPORTS[tag],
            _TAG_SECTIONS[tag],
            _TAG_STRINGS[tag],
        ),
        "answer": tag,
        "first_seen": first_seen,
        "time_period": assign_time_period(first_seen),
    }


# ---------------------------------------------------------------------------
# Synthetic dataset generation
# ---------------------------------------------------------------------------


def generate_sample_dataset(n: int = 60, out_jsonl: Path = OUT_JSONL) -> int:
    """Write *n* synthetic SOREL records to *out_jsonl*.

    Samples are distributed evenly across behavioral tags and time periods so
    that temporal drift plots (accuracy vs. time period) are meaningful even
    on the synthetic dataset.  Returns the number of records written.
    """
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    k = len(SOREL_TAGS)
    n_periods = len(_TIME_PERIODS)
    written = 0
    with open(out_jsonl, "w", encoding="utf-8") as fh:
        for i in range(n):
            tag = SOREL_TAGS[i % k]
            period_idx = i % n_periods
            period_name, ts_start, ts_end = _TIME_PERIODS[period_idx]
            span = ts_end - ts_start
            # Spread first_seen evenly inside the chosen half-year bucket
            first_seen = ts_start + span * (i // n_periods) // max(n // n_periods, 1)
            sha256 = hashlib.sha256(f"synthetic-sorel-{i}".encode()).hexdigest()
            fh.write(json.dumps(make_record(sha256, tag, first_seen)) + "\n")
            written += 1
    return written


# ---------------------------------------------------------------------------
# Real data fetch from S3 via AWS CLI
# ---------------------------------------------------------------------------


def _check_aws_cli() -> None:
    """Raise RuntimeError if AWS CLI is not found on PATH."""
    result = subprocess.run(
        ["aws", "--version"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "AWS CLI not found.  Install it from https://aws.amazon.com/cli/ "
            "and ensure it is on your PATH before using --fetch."
        )


def download_meta_db(dest: Path) -> None:
    """Stream meta.db from the public SOREL S3 bucket using the AWS CLI."""
    _check_aws_cli()
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {_S3_META_DB} → {dest}  (≈3.5 GB, no credentials required)")
    result = subprocess.run(
        ["aws", "s3", "cp", _S3_META_DB, str(dest), "--no-sign-request"],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"aws s3 cp failed (exit {result.returncode}).  "
            "Ensure the S3 bucket is accessible and you have accepted the SOREL Terms of Use."
        )


def sample_from_meta_db(db_path: Path, n: int, out_jsonl: Path) -> int:
    """Sample *n* malware records from a local meta.db and write sorel.jsonl.

    The dominant behavioral tag is determined by the highest non-zero tag count.
    Samples that have no tag counts > 0 are skipped.  Returns records written.
    """
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    tag_cols = ", ".join(SOREL_TAGS)
    query = (
        f"SELECT sha256, first_seen, {tag_cols} "
        f"FROM meta WHERE label = 1 LIMIT {n * 4}"  # over-fetch to account for untagged rows
    )
    with sqlite3.connect(str(db_path)) as con:
        rows = con.execute(query).fetchall()

    with open(out_jsonl, "w", encoding="utf-8") as fh:
        for row in rows:
            if written >= n:
                break
            sha256 = row[0]
            first_seen = int(row[1]) if row[1] is not None else 0
            tag_counts = dict(zip(SOREL_TAGS, row[2:]))
            # Pick the tag with the highest count; skip rows with all zeros
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
        help="Generate N synthetic records (default 60). Used without --fetch for pipeline testing.",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Download meta.db from S3 (requires AWS CLI). Combine with --sample N to limit output.",
    )
    args = parser.parse_args()

    n = args.sample if args.sample is not None else 60

    if args.fetch:
        if not META_DB.exists():
            download_meta_db(META_DB)
        else:
            print(f"Using cached {META_DB}")
        written = sample_from_meta_db(META_DB, n, OUT_JSONL)
        print(f"Wrote {written} records from meta.db → {OUT_JSONL}")
        return

    written = generate_sample_dataset(n=n)
    print(f"Wrote {written} synthetic records → {OUT_JSONL}")


if __name__ == "__main__":
    main()
