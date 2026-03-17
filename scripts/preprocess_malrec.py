"""preprocess_malrec.py — prepare the Malrec execution-trace dataset.

Usage (quick synthetic sample for pipeline testing, no network):
    python scripts/preprocess_malrec.py --sample [N]

Usage (process an already-extracted Malrec directory):
    python scripts/preprocess_malrec.py --path data/datasets/malrec/raw/

Both modes write data/datasets/malrec/malrec.jsonl in the unified JSONL format:
    {"id": ..., "dataset": "malrec", "artifact_type": "execution_trace",
     "task": ..., "input": ..., "answer": ...}
which is consumed by tasks/malrec_task.py and data/malrec_loader.py.

Task types produced:
    behavior_explanation  — execution trace → behavior keyword
    capability_extraction — syscall / system-event sequence → capability name
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

OUTPUT = "data/datasets/malrec/malrec.jsonl"

# ---------------------------------------------------------------------------
# Synthetic execution-trace samples
# ---------------------------------------------------------------------------
_SYNTHETIC_SAMPLES = [
    # --- behavior_explanation ---
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "NtOpenProcess(pid=588, access=PROCESS_ALL_ACCESS)\n"
            "NtAllocateVirtualMemory(pid=588, size=0x1000, protect=PAGE_EXECUTE_READWRITE)\n"
            "NtWriteVirtualMemory(pid=588, addr=0x2A000000, size=0x1000)\n"
            "NtCreateThreadEx(pid=588, start=0x2A000000)"
        ),
        "answer": "process injection",
    },
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "NtCreateFile(path=C:\\Windows\\Temp\\svchost32.exe, access=WRITE)\n"
            "NtWriteFile(path=C:\\Windows\\Temp\\svchost32.exe)\n"
            "NtSetValueKey(key=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, "
            "value=svchost32)\n"
            "NtCreateProcess(image=C:\\Windows\\Temp\\svchost32.exe)"
        ),
        "answer": "persistence",
    },
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "NtCreateFile(path=C:\\Users\\victim\\Documents\\report.docx, access=READ)\n"
            "NtReadFile(path=C:\\Users\\victim\\Documents\\report.docx)\n"
            "BCryptEncrypt(data=report.docx)\n"
            "NtCreateFile(path=C:\\Users\\victim\\Documents\\report.docx.locked, access=WRITE)\n"
            "NtWriteFile(path=C:\\Users\\victim\\Documents\\report.docx.locked)\n"
            "NtDeleteFile(path=C:\\Users\\victim\\Documents\\report.docx)"
        ),
        "answer": "ransomware",
    },
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "NtQuerySystemInformation(class=SystemProcessInformation)\n"
            "NtQueryInformationProcess(pid=4, class=ProcessBasicInformation)\n"
            "NtOpenKey(key=HKLM\\SYSTEM\\CurrentControlSet\\Services)\n"
            "NtEnumerateValueKey(hKey)\n"
            "GetComputerNameW\n"
            "GetUserNameW"
        ),
        "answer": "discovery",
    },
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "WSASocket(AF_INET, SOCK_STREAM)\n"
            "connect(addr=185.220.101.5:443)\n"
            "send(data=<encrypted beacon>)\n"
            "recv(data=<C2 command>)\n"
            "ShellExecuteW(cmd=<decoded command>)"
        ),
        "answer": "command and control",
    },
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "FindFirstFileW(path=C:\\Users\\*)\n"
            "FindNextFileW\n"
            "NtReadFile(path=C:\\Users\\victim\\AppData\\Roaming\\Mozilla\\Firefox\\profiles.ini)\n"
            "NtReadFile(path=C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\...\\Login Data)\n"
            "send(addr=203.0.113.42:80, data=<credentials>)"
        ),
        "answer": "credential theft",
    },
    {
        "artifact_type": "execution_trace",
        "task": "behavior_explanation",
        "input": (
            "NtCreateFile(path=C:\\Windows\\System32\\drivers\\rootkit.sys, access=WRITE)\n"
            "NtLoadDriver(driver=rootkit.sys)\n"
            "ZwSetSystemInformation(class=SystemLoadAndCallImage)\n"
            "PsSetCreateProcessNotifyRoutine"
        ),
        "answer": "rootkit",
    },
    # --- capability_extraction ---
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "NtOpenProcess\n"
            "NtAllocateVirtualMemory\n"
            "NtWriteVirtualMemory\n"
            "NtCreateThreadEx"
        ),
        "answer": "process injection",
    },
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "BCryptOpenAlgorithmProvider\n"
            "BCryptSetProperty\n"
            "BCryptGenerateSymmetricKey\n"
            "BCryptEncrypt"
        ),
        "answer": "encryption",
    },
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "NtQuerySystemInformation\n"
            "GetComputerNameW\n"
            "GetUserNameW\n"
            "NtQueryInformationProcess"
        ),
        "answer": "system enumeration",
    },
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "WSASocket\n"
            "connect\n"
            "send\n"
            "recv"
        ),
        "answer": "network communication",
    },
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "NtSetValueKey [HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"
            "NtCreateFile [Startup folder]\n"
            "CreateService"
        ),
        "answer": "persistence",
    },
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "FindFirstFileW\n"
            "NtReadFile [Login Data]\n"
            "NtReadFile [profiles.ini]\n"
            "CryptUnprotectData"
        ),
        "answer": "credential access",
    },
    {
        "artifact_type": "execution_trace",
        "task": "capability_extraction",
        "input": (
            "SetWindowsHookEx [WH_KEYBOARD_LL]\n"
            "GetAsyncKeyState\n"
            "NtWriteFile [keylog.dat]"
        ),
        "answer": "keylogging",
    },
]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_trace(text: str) -> str:
    """Strip redundant whitespace from execution trace lines."""
    lines = [re.sub(r" +", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


# ---------------------------------------------------------------------------
# Synthetic dataset generation
# ---------------------------------------------------------------------------

def generate_sample_dataset(n: int, output: str = OUTPUT) -> int:
    """Write *n* synthetic Malrec records to *output*. Returns records written."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    base = _SYNTHETIC_SAMPLES
    k = len(base)
    written = 0
    with open(output, "w", encoding="utf-8") as fh:
        for i in range(n):
            template = base[i % k]
            uid = hashlib.sha256(f"malrec-{i}".encode()).hexdigest()[:12]
            record = {
                "id": f"malrec_{template['task']}_{i:04d}",
                "dataset": "malrec",
                "artifact_type": template["artifact_type"],
                "task": template["task"],
                "input": normalize_trace(template["input"]),
                "answer": template["answer"],
                "sample_id": uid,
            }
            fh.write(json.dumps(record) + "\n")
            written += 1
    return written


# ---------------------------------------------------------------------------
# Real on-disk processing
# ---------------------------------------------------------------------------

def process_malrec_tree(base_path: str, output: str = OUTPUT) -> int:
    """Walk *base_path* for .log/.txt execution-trace files and emit tasks."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    seen: set[str] = set()

    with open(output, "w", encoding="utf-8") as fh:
        for root, _, files in os.walk(base_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                if Path(fpath).suffix.lower() not in (".log", ".txt", ".trace"):
                    continue
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                normalized = normalize_trace(content)
                digest = hashlib.sha256(normalized.encode()).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)

                record = {
                    "id": f"malrec_behavior_{digest[:8]}",
                    "dataset": "malrec",
                    "artifact_type": "execution_trace",
                    "task": "behavior_explanation",
                    "input": normalized[:2000],
                    "answer": "UNKNOWN",
                    "sample_id": digest[:12],
                }
                fh.write(json.dumps(record) + "\n")
                written += 1

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare Malrec execution-trace dataset.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--sample",
        nargs="?",
        const=60,
        type=int,
        metavar="N",
        help="Generate N synthetic records (default 60).",
    )
    group.add_argument(
        "--path",
        type=str,
        metavar="DIR",
        help="Process execution-trace files from DIR recursively.",
    )
    parser.add_argument("--output", default=OUTPUT)
    args = parser.parse_args()

    if args.path:
        n = process_malrec_tree(args.path, args.output)
        print(f"Processed {n} records from '{args.path}' → '{args.output}'")
    else:
        n_req = args.sample if args.sample is not None else 60
        n = generate_sample_dataset(n_req, args.output)
        print(f"Generated {n} synthetic records → '{args.output}'")


if __name__ == "__main__":
    main()
