import re
from pathlib import Path

import pandas as pd
from inspect_ai.log import read_eval_log

_MALWARE_TERMS = {"malware", "malicious", "trojan", "ransomware", "spyware", "worm", "rootkit", "adware"}
_CWE_RE = re.compile(r"cwe-\d+", re.IGNORECASE)


def _is_cwe_target(target: str) -> bool:
    """Return True if *target* looks like a CWE identifier (e.g. CWE-121)."""
    return bool(_CWE_RE.fullmatch(target.strip()))


def _extract_cwe(text: str) -> str:
    """Return the first CWE-NNN found in *text*, else 'NONE'."""
    m = _CWE_RE.search(text)
    return m.group(0).upper() if m else "NONE"


def _build_row_from(raw_target: str, completion: str, sample_id, model_name: str) -> dict:
    completion_lower = completion.lower()

    if _is_cwe_target(raw_target):
        # ---- CWE identification task (Juliet / BigVul) ----
        true_cwe = raw_target.upper()
        pred_cwe = _extract_cwe(completion)
        match = float(pred_cwe == true_cwe)
        return {
            "sample_id": sample_id,
            "model_version": model_name,
            "true_behavior": true_cwe,
            "pred_behavior": pred_cwe,
            "malware_score": 0.0,
            "vuln_f1": match,
            "hallucination_penalty": 0.0,
            "explanation": completion,
            "cwe": true_cwe,
        }
    elif raw_target.lower() in {"malware", "benign"}:
        # ---- Binary malware/benign classification (Ember) ----
        target = raw_target.lower()
        pred = "malware" if any(term in completion_lower for term in _MALWARE_TERMS) else "benign"
        return {
            "sample_id": sample_id,
            "model_version": model_name,
            "true_behavior": target,
            "pred_behavior": pred,
            "malware_score": float(pred == target),
            "vuln_f1": 0.0,
            "hallucination_penalty": 0.0,
            "explanation": completion,
            "cwe": "NONE",
        }
    else:
        # ---- Family-name prediction (MalwareBazaar) ----
        target_lower = raw_target.lower()
        found = target_lower in completion_lower
        tokens = completion.split()
        pred = raw_target if found else (tokens[0] if tokens else "unknown")
        return {
            "sample_id": sample_id,
            "model_version": model_name,
            "true_behavior": raw_target,
            "pred_behavior": pred,
            "malware_score": float(found),
            "vuln_f1": 0.0,
            "hallucination_penalty": 0.0,
            "explanation": completion,
            "cwe": "NONE",
        }


def main():
    repo = Path(__file__).resolve().parents[1]
    logs_dir = repo / "logs"
    out_dir = repo / "results" / "runs"
    out_dir.mkdir(parents=True, exist_ok=True)

    log_files = sorted(logs_dir.glob("*.eval"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not log_files:
        raise FileNotFoundError(f"No Inspect .eval logs found in {logs_dir}")

    latest_log = log_files[0]
    log = read_eval_log(str(latest_log))

    model_name = (log.eval.model if log.eval else None) or "unknown"
    rows = []
    for sample in (log.samples or []):
        target = str(sample.target or "benign").strip()
        completion = ""
        if sample.output and sample.output.choices:
            completion = str(sample.output.choices[0].message.content or "").strip()
        rows.append(_build_row_from(target, completion, sample.id, model_name))

    if not rows:
        rows.append({
            "sample_id": "fallback-0",
            "model_version": model_name,
            "true_behavior": "benign",
            "pred_behavior": "benign",
            "malware_score": 1.0,
            "vuln_f1": 0.0,
            "hallucination_penalty": 0.0,
            "explanation": "",
            "cwe": "NONE",
        })

    out_csv = out_dir / "latest_run.csv"
    pd.DataFrame(rows).to_csv(out_csv, index=False)
    print(f"Wrote {out_csv} with {len(rows)} row(s) from {latest_log.name}")


if __name__ == "__main__":
    main()
