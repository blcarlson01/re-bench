"""prediction_normalizer.py — prediction normalization utilities.

Implements the normalization pipeline from the bench_score spec:
  1. lowercase conversion
  2. whitespace cleanup
  3. synonym mapping
  4. MITRE technique normalization

Normalize predictions and references before scoring to reduce surface-level
mismatches that obscure true model understanding.
"""

import re

# ---------------------------------------------------------------------------
# MITRE technique synonym table
# Maps free-text descriptions and aliases → canonical technique ID
# ---------------------------------------------------------------------------
_MITRE_SYNONYMS: dict[str, str] = {
    # T1055 – Process Injection
    "process injection": "T1055",
    "dll injection": "T1055",
    "remote thread injection": "T1055",
    "t1055": "T1055",
    # T1082 – System Information Discovery
    "system information discovery": "T1082",
    "system info discovery": "T1082",
    "t1082": "T1082",
    # T1547 – Boot/Autostart Execution (Registry Run Keys)
    "registry run key": "T1547",
    "registry persistence": "T1547",
    "autostart execution": "T1547",
    "t1547": "T1547",
    # T1059 – Command and Scripting Interpreter
    "command execution": "T1059",
    "script execution": "T1059",
    "cmd execution": "T1059",
    "t1059": "T1059",
    # T1027 – Obfuscated Files or Information
    "obfuscation": "T1027",
    "obfuscated files": "T1027",
    "code obfuscation": "T1027",
    "t1027": "T1027",
    # T1071 – Application Layer Protocol (C2)
    "network communication": "T1071",
    "application layer protocol": "T1071",
    "command and control": "T1071",
    "c2 communication": "T1071",
    "t1071": "T1071",
    # T1005 – Data from Local System
    "file enumeration": "T1005",
    "data from local system": "T1005",
    "file system enumeration": "T1005",
    "t1005": "T1005",
    # T1574 – Hijack Execution Flow (DLL Search Order)
    "dll hijacking": "T1574",
    "hijack execution flow": "T1574",
    "dll search order hijacking": "T1574",
    "t1574": "T1574",
    # T1056 – Input Capture / Keylogging
    "keylogging": "T1056",
    "input capture": "T1056",
    "keystroke logging": "T1056",
    "t1056": "T1056",
    # T1543 – Create or Modify System Process (Service)
    "service installation": "T1543",
    "create service": "T1543",
    "modify service": "T1543",
    "t1543": "T1543",
    # T1105 – Ingress Tool Transfer (Download)
    "payload download": "T1105",
    "ingress tool transfer": "T1105",
    "file download": "T1105",
    "t1105": "T1105",
}

# Capability synonym table — maps variant descriptions to canonical names
_CAPABILITY_SYNONYMS: dict[str, str] = {
    "process injection": "process injection",
    "dll injection": "process injection",
    "remote thread injection": "process injection",
    "registry persistence": "persistence",
    "registry run key persistence": "persistence",
    "autostart persistence": "persistence",
    "network communication": "network communication",
    "c2 communication": "network communication",
    "command and control": "network communication",
    "encryption": "encryption",
    "encrypt": "encryption",
    "file system enumeration": "file system enumeration",
    "file enumeration": "file system enumeration",
    "service installation": "service installation",
    "payload download": "payload download",
    "file download": "payload download",
    "keylogging": "keylogging",
    "keystroke logging": "keylogging",
    "obfuscation": "obfuscation",
    "system enumeration": "system enumeration",
    "system information discovery": "system enumeration",
    "credential theft": "credential theft",
    "credential access": "credential theft",
    "discovery": "discovery",
    "rootkit": "rootkit",
    "ransomware": "ransomware",
}


def normalize_prediction(text: str) -> str:
    """Apply standard normalization: lowercase, whitespace cleanup, leading/trailing strip."""
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    text = text.strip()
    return text


def normalize_mitre(text: str) -> str:
    """Normalize a raw prediction to a canonical MITRE technique ID if possible.

    Falls back to the base-normalized text if no synonym match is found.
    """
    base = normalize_prediction(text)

    # Direct lookup in synonym table
    if base in _MITRE_SYNONYMS:
        return _MITRE_SYNONYMS[base]

    # Match bare technique ID pattern (e.g. "t1055.001" → "T1055")
    m = re.search(r"\bt(\d{4})(?:\.\d+)?\b", base)
    if m:
        return f"T{m.group(1)}"

    return base


def normalize_capability(text: str) -> str:
    """Normalize a capability label to a canonical form.

    Falls back to the base-normalized text if no synonym match is found.
    """
    base = normalize_prediction(text)
    return _CAPABILITY_SYNONYMS.get(base, base)


def normalize_family(text: str) -> str:
    """Normalize a malware family name (lowercase + whitespace only)."""
    return normalize_prediction(text)
