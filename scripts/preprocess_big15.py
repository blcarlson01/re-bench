"""preprocess_big15.py — prepare the BIG-15 malware assembly dataset.

Usage (quick synthetic sample for pipeline testing, no download):
    python scripts/preprocess_big15.py --sample [N]

Usage (process an already-extracted BIG-15 .asm tree):
    python scripts/preprocess_big15.py --path data/datasets/big15/asm/

Both modes write data/datasets/big15/big15.jsonl in the unified JSONL format:
    {"id": ..., "dataset": "big15", "artifact_type": "assembly",
     "task": ..., "input": ..., "answer": ...}
which is consumed by tasks/big15_task.py and data/big15_loader.py.

Task types produced:
    mitre_mapping       — assembly snippet → ATT&CK technique ID (T1055, …)
    family_classification — assembly snippet → malware family name
    assembly_understanding — assembly snippet → behavior keyword
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

OUTPUT = "data/datasets/big15/big15.jsonl"

# ---------------------------------------------------------------------------
# BIG-15 family names (15 families from the Microsoft Kaggle competition)
# ---------------------------------------------------------------------------
BIG15_FAMILIES = [
    "Ramnit", "Lollipop", "Kelihos_ver3", "Vundo", "Simda",
    "Tracur", "Kelihos_ver1", "Obfuscator.ACY", "Gatak",
    "BHO", "Lolyda.AA1", "Lolyda.AA2", "Lolyda.AA3", "Lolyda.AT",
    "Fakerean",
]

# ---------------------------------------------------------------------------
# Synthetic samples: (artifact_type, task, input, answer)
# ---------------------------------------------------------------------------
_SYNTHETIC_SAMPLES = [
    # --- mitre_mapping ---
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "push    PROCESS_ALL_ACCESS\n"
            "push    0\n"
            "push    [target_pid]\n"
            "call    OpenProcess\n"
            "call    VirtualAllocEx\n"
            "call    WriteProcessMemory\n"
            "call    CreateRemoteThread"
        ),
        "answer": "T1055",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "call    GetComputerNameA\n"
            "call    GetSystemInfo\n"
            "call    GetVersionExA\n"
            "call    GetUserNameA"
        ),
        "answer": "T1082",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "push    offset szSubKey\n"
            "push    HKEY_LOCAL_MACHINE\n"
            "call    RegOpenKeyExA\n"
            "push    REG_SZ\n"
            "push    offset szValue\n"
            "call    RegSetValueExA\n"
            "call    RegCloseKey"
        ),
        "answer": "T1547",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "push    offset cmd_str\n"
            "call    WinExec\n"
            "push    SW_HIDE\n"
            "push    offset cmdline\n"
            "call    CreateProcessA"
        ),
        "answer": "T1059",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "push    hKey\n"
            "call    CryptEncrypt\n"
            "xor     eax, 0DEADBEEFh\n"
            "rol     eax, 5\n"
            "call    CryptHashData"
        ),
        "answer": "T1027",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "call    WSAStartup\n"
            "call    socket\n"
            "call    connect\n"
            "call    send\n"
            "call    recv\n"
            "call    closesocket"
        ),
        "answer": "T1071",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "call    FindFirstFileA\n"
            "call    FindNextFileA\n"
            "call    ReadFile\n"
            "call    CopyFileA"
        ),
        "answer": "T1005",
    },
    {
        "artifact_type": "assembly",
        "task": "mitre_mapping",
        "input": (
            "call    LoadLibraryA\n"
            "call    GetProcAddress\n"
            "push    offset dll_path\n"
            "call    SetDllDirectoryA"
        ),
        "answer": "T1574",
    },
    # --- family_classification ---
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Ramnit dropper stub\n"
            "push    ebp\n"
            "mov     ebp, esp\n"
            "call    GetTempPathA\n"
            "call    CreateFileA\n"
            "call    WriteFile\n"
            "call    ShellExecuteA"
        ),
        "answer": "Ramnit",
    },
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Kelihos botnet loader\n"
            "call    InternetOpenA\n"
            "call    InternetOpenUrlA\n"
            "call    InternetReadFile\n"
            "call    CreateThread"
        ),
        "answer": "Kelihos_ver3",
    },
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Vundo adware install\n"
            "call    RegCreateKeyExA\n"
            "push    offset clsid_str\n"
            "call    RegSetValueExA\n"
            "call    CoCreateInstance"
        ),
        "answer": "Vundo",
    },
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Obfuscator.ACY unpacking loop\n"
            "mov     ecx, 0FFFFh\n"
            "xor_loop:\n"
            "  xor   [edi+ecx], 0A5h\n"
            "  sub   ecx, 1\n"
            "  jnz   xor_loop\n"
            "jmp     edi"
        ),
        "answer": "Obfuscator.ACY",
    },
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Gatak loader\n"
            "call    CreateMutexA\n"
            "call    GetLastError\n"
            "cmp     eax, ERROR_ALREADY_EXISTS\n"
            "jz      already_running\n"
            "call    DownloadFileA"
        ),
        "answer": "Gatak",
    },
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Simda rootkit hook\n"
            "push    fs:[0]\n"
            "call    ZwSetSystemInformation\n"
            "call    PsSetCreateProcessNotifyRoutine\n"
            "call    IoCreateDevice"
        ),
        "answer": "Simda",
    },
    {
        "artifact_type": "assembly",
        "task": "family_classification",
        "input": (
            "; Tracur redirect stub\n"
            "call    InternetSetOptionA\n"
            "push    offset proxy_url\n"
            "call    InternetConnectA\n"
            "call    HttpOpenRequestA"
        ),
        "answer": "Tracur",
    },
    # --- assembly_understanding ---
    {
        "artifact_type": "assembly",
        "task": "assembly_understanding",
        "input": (
            "call    OpenProcess\n"
            "call    VirtualAllocEx\n"
            "call    WriteProcessMemory\n"
            "call    CreateRemoteThread"
        ),
        "answer": "process injection",
    },
    {
        "artifact_type": "assembly",
        "task": "assembly_understanding",
        "input": (
            "push    HKEY_LOCAL_MACHINE\n"
            "push    offset run_key\n"
            "call    RegOpenKeyExA\n"
            "call    RegSetValueExA"
        ),
        "answer": "registry persistence",
    },
    {
        "artifact_type": "assembly",
        "task": "assembly_understanding",
        "input": (
            "xor     eax, 0xDEADBEEF\n"
            "rol     eax, 7\n"
            "not     eax\n"
            "xor     eax, 0x12345678"
        ),
        "answer": "obfuscation",
    },
    {
        "artifact_type": "assembly",
        "task": "assembly_understanding",
        "input": (
            "call    WSAStartup\n"
            "call    socket\n"
            "call    connect\n"
            "call    send\n"
            "call    recv"
        ),
        "answer": "network communication",
    },
    {
        "artifact_type": "assembly",
        "task": "assembly_understanding",
        "input": (
            "call    CryptAcquireContextA\n"
            "call    CryptCreateHash\n"
            "call    CryptHashData\n"
            "call    CryptEncrypt"
        ),
        "answer": "encryption",
    },
]


# ---------------------------------------------------------------------------
# Normalization: strip memory addresses, clean whitespace
# ---------------------------------------------------------------------------

def normalize_snippet(text: str) -> str:
    """Remove leading hex addresses and normalize whitespace."""
    text = re.sub(r"^[0-9A-Fa-f]{6,8}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s+\n", "\n", text)
    return text.strip()


# ---------------------------------------------------------------------------
# Synthetic dataset generation
# ---------------------------------------------------------------------------

def generate_sample_dataset(n: int, output: str = OUTPUT) -> int:
    """Write *n* synthetic BIG-15 records to *output*. Returns records written."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    base = _SYNTHETIC_SAMPLES
    k = len(base)
    written = 0
    with open(output, "w", encoding="utf-8") as fh:
        for i in range(n):
            template = base[i % k]
            family = BIG15_FAMILIES[i % len(BIG15_FAMILIES)]
            uid = hashlib.sha256(f"big15-{i}".encode()).hexdigest()[:12]
            record = {
                "id": f"big15_{template['task']}_{i:04d}",
                "dataset": "big15",
                "artifact_type": template["artifact_type"],
                "task": template["task"],
                "input": normalize_snippet(template["input"]),
                "answer": template["answer"],
                "sample_id": uid,
                "source_family": family,
            }
            fh.write(json.dumps(record) + "\n")
            written += 1
    return written


# ---------------------------------------------------------------------------
# Real on-disk processing
# ---------------------------------------------------------------------------

def process_asm_tree(base_path: str, output: str = OUTPUT) -> int:
    """Walk *base_path* for .asm files and emit mitre_mapping/family_classification tasks."""
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    seen: set[str] = set()

    with open(output, "w", encoding="utf-8") as fh:
        for root, _, files in os.walk(base_path):
            for fname in files:
                if not fname.endswith(".asm"):
                    continue
                fpath = os.path.join(root, fname)
                # Derive family from parent directory name
                family = Path(fpath).parent.name
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                normalized = normalize_snippet(content)
                digest = hashlib.sha256(normalized.encode()).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)

                # Emit mitre_mapping task (answer left as placeholder for real labelling)
                record = {
                    "id": f"big15_mitre_{digest[:8]}",
                    "dataset": "big15",
                    "artifact_type": "assembly",
                    "task": "mitre_mapping",
                    "input": normalized[:2000],  # cap at 2 000 chars
                    "answer": "UNKNOWN",
                    "sample_id": digest[:12],
                    "source_family": family,
                }
                fh.write(json.dumps(record) + "\n")
                written += 1

                # Also emit family_classification task
                record2 = dict(record)
                record2["id"] = f"big15_family_{digest[:8]}"
                record2["task"] = "family_classification"
                record2["answer"] = family
                fh.write(json.dumps(record2) + "\n")
                written += 1

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare BIG-15 assembly dataset.")
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
        help="Process .asm files from DIR recursively.",
    )
    parser.add_argument("--output", default=OUTPUT)
    args = parser.parse_args()

    if args.path:
        n = process_asm_tree(args.path, args.output)
        print(f"Processed {n} records from '{args.path}' → '{args.output}'")
    else:
        n_req = args.sample if args.sample is not None else 60
        n = generate_sample_dataset(n_req, args.output)
        print(f"Generated {n} synthetic records → '{args.output}'")


if __name__ == "__main__":
    main()
