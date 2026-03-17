"""preprocess_meld.py — prepare the MELD API-trace / sandbox dataset.

Usage (quick synthetic sample for pipeline testing, no network):
    python scripts/preprocess_meld.py --sample [N]

Usage (process an already-extracted MELD directory):
    python scripts/preprocess_meld.py --path data/datasets/meld/raw/

Both modes write data/datasets/meld/meld.jsonl in the unified JSONL format:
    {"id": ..., "dataset": "meld", "artifact_type": ...,
     "task": ..., "input": ..., "answer": ...}
which is consumed by tasks/meld_task.py and data/meld_loader.py.

Task types produced:
    capability_extraction — API sequence → primary capability name
    mitre_mapping         — API sequence → ATT&CK technique ID (T1055, …)
    behavior_explanation  — sandbox report snippet → behavior keyword
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

OUTPUT = "data/datasets/meld/meld.jsonl"

# ---------------------------------------------------------------------------
# Behavioral API groupings with MITRE mappings and capability labels
# ---------------------------------------------------------------------------
_SYNTHETIC_SAMPLES = [
    # --- capability_extraction (API traces) ---
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "OpenProcess\n"
            "VirtualAllocEx\n"
            "WriteProcessMemory\n"
            "CreateRemoteThread"
        ),
        "answer": "process injection",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "RegCreateKeyExA\n"
            "RegSetValueExA\n"
            "RegCloseKey"
        ),
        "answer": "registry persistence",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "WSAStartup\n"
            "socket\n"
            "connect\n"
            "send\n"
            "recv\n"
            "closesocket"
        ),
        "answer": "network communication",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "CryptAcquireContextA\n"
            "CryptCreateHash\n"
            "CryptHashData\n"
            "CryptEncrypt\n"
            "CryptDestroyHash"
        ),
        "answer": "encryption",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "FindFirstFileA\n"
            "FindNextFileA\n"
            "ReadFile\n"
            "WriteFile\n"
            "DeleteFileA"
        ),
        "answer": "file system enumeration",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "CreateService\n"
            "OpenSCManager\n"
            "StartService\n"
            "ChangeServiceConfig"
        ),
        "answer": "service installation",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "InternetOpenA\n"
            "InternetOpenUrlA\n"
            "InternetReadFile\n"
            "URLDownloadToFileA"
        ),
        "answer": "payload download",
    },
    {
        "artifact_type": "api_trace",
        "task": "capability_extraction",
        "input": (
            "SetWindowsHookExA\n"
            "CallNextHookEx\n"
            "GetAsyncKeyState\n"
            "GetForegroundWindow"
        ),
        "answer": "keylogging",
    },
    # --- mitre_mapping (API traces) ---
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread"
        ),
        "answer": "T1055",
    },
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "RegOpenKeyExA -> RegSetValueExA -> RegCloseKey [HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]"
        ),
        "answer": "T1547",
    },
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "WSAStartup -> socket -> connect -> send -> recv"
        ),
        "answer": "T1071",
    },
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "SetWindowsHookExA -> GetAsyncKeyState -> WriteFile [keylog.txt]"
        ),
        "answer": "T1056",
    },
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "CreateService -> OpenSCManager -> StartService [malware_svc]"
        ),
        "answer": "T1543",
    },
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "InternetOpenA -> InternetOpenUrlA -> InternetReadFile -> CreateFileA -> WriteFile"
        ),
        "answer": "T1105",
    },
    {
        "artifact_type": "api_trace",
        "task": "mitre_mapping",
        "input": (
            "GetComputerNameA -> GetUserNameA -> GetSystemInfo -> send [C2 beacon]"
        ),
        "answer": "T1082",
    },
    # --- behavior_explanation (sandbox report snippets) ---
    {
        "artifact_type": "sandbox_report",
        "task": "behavior_explanation",
        "input": (
            "Process: malware.exe\n"
            "API calls: OpenProcess(pid=1234) -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread\n"
            "Target: explorer.exe"
        ),
        "answer": "process injection",
    },
    {
        "artifact_type": "sandbox_report",
        "task": "behavior_explanation",
        "input": (
            "Registry activity:\n"
            "  HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32 = C:\\Windows\\Temp\\payload.exe\n"
            "File created: C:\\Windows\\Temp\\payload.exe"
        ),
        "answer": "persistence",
    },
    {
        "artifact_type": "sandbox_report",
        "task": "behavior_explanation",
        "input": (
            "Network activity:\n"
            "  DNS query: evil-c2.example.com\n"
            "  TCP connect: 185.220.101.5:443\n"
            "  HTTP POST /gate.php (encrypted payload)"
        ),
        "answer": "command and control",
    },
    {
        "artifact_type": "sandbox_report",
        "task": "behavior_explanation",
        "input": (
            "File system:\n"
            "  FindFirstFile(*.doc)\n"
            "  ReadFile -> CryptEncrypt -> WriteFile (*.encrypted)\n"
            "  DeleteFile (originals)\n"
            "Dropped: DECRYPT_INSTRUCTIONS.txt"
        ),
        "answer": "ransomware",
    },
    {
        "artifact_type": "sandbox_report",
        "task": "behavior_explanation",
        "input": (
            "Process spawn: cmd.exe /c whoami\n"
            "Process spawn: cmd.exe /c net localgroup administrators\n"
            "Process spawn: cmd.exe /c ipconfig /all"
        ),
        "answer": "discovery",
    },
]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_api_trace(text: str) -> str:
    """Standardize API name casing and strip redundant whitespace."""
    text = re.sub(r" +", " ", text)
    text = text.strip()
    return text


# ---------------------------------------------------------------------------
# Synthetic dataset generation
# ---------------------------------------------------------------------------

def generate_sample_dataset(n: int, output: str = OUTPUT) -> int:
    """Write *n* synthetic MELD records to *output*. Returns records written."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    base = _SYNTHETIC_SAMPLES
    k = len(base)
    written = 0
    with open(output, "w", encoding="utf-8") as fh:
        for i in range(n):
            template = base[i % k]
            uid = hashlib.sha256(f"meld-{i}".encode()).hexdigest()[:12]
            record = {
                "id": f"meld_{template['task']}_{i:04d}",
                "dataset": "meld",
                "artifact_type": template["artifact_type"],
                "task": template["task"],
                "input": normalize_api_trace(template["input"]),
                "answer": template["answer"],
                "sample_id": uid,
            }
            fh.write(json.dumps(record) + "\n")
            written += 1
    return written


# ---------------------------------------------------------------------------
# Real on-disk processing
# ---------------------------------------------------------------------------

def process_meld_tree(base_path: str, output: str = OUTPUT) -> int:
    """Walk *base_path* for .txt/.json API-trace files and emit tasks."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    seen: set[str] = set()

    with open(output, "w", encoding="utf-8") as fh:
        for root, _, files in os.walk(base_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                suffix = Path(fpath).suffix.lower()
                if suffix not in (".txt", ".json", ".log"):
                    continue
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                normalized = normalize_api_trace(content)
                digest = hashlib.sha256(normalized.encode()).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)

                artifact_type = "sandbox_report" if suffix == ".json" else "api_trace"
                record = {
                    "id": f"meld_mitre_{digest[:8]}",
                    "dataset": "meld",
                    "artifact_type": artifact_type,
                    "task": "mitre_mapping",
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
    parser = argparse.ArgumentParser(description="Prepare MELD API-trace dataset.")
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
        help="Process API-trace files from DIR recursively.",
    )
    parser.add_argument("--output", default=OUTPUT)
    args = parser.parse_args()

    if args.path:
        n = process_meld_tree(args.path, args.output)
        print(f"Processed {n} records from '{args.path}' → '{args.output}'")
    else:
        n_req = args.sample if args.sample is not None else 60
        n = generate_sample_dataset(n_req, args.output)
        print(f"Generated {n} synthetic records → '{args.output}'")


if __name__ == "__main__":
    main()
