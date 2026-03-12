import json
import subprocess
from pathlib import Path

import pandas as pd


def main():
    repo = Path(__file__).resolve().parents[1]
    logs_dir = repo / "logs"
    out_dir = repo / "results" / "runs"
    out_dir.mkdir(parents=True, exist_ok=True)

    log_files = sorted(logs_dir.glob("*.eval"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not log_files:
        raise FileNotFoundError(f"No Inspect .eval logs found in {logs_dir}")

    latest_log = log_files[0]
    proc = subprocess.run(
        ["inspect", "log", "dump", str(latest_log)],
        check=True,
        capture_output=True,
        text=True,
    )
    obj = json.loads(proc.stdout)

    model_name = obj.get("eval", {}).get("model", "unknown")
    rows = []
    for sample in obj.get("samples", []):
        target = str(sample.get("target", "benign")).strip().lower()
        completion = str(sample.get("output", {}).get("completion", "")).strip()
        completion_lower = completion.lower()
        _malware_terms = {"malware", "malicious", "trojan", "ransomware", "spyware", "worm", "rootkit", "adware"}
        pred = "malware" if any(term in completion_lower for term in _malware_terms) else "benign"

        rows.append(
            {
                "sample_id": sample.get("id", "unknown"),
                "model_version": model_name,
                "true_behavior": target,
                "pred_behavior": pred,
                "malware_score": float(pred == target),
                "vuln_f1": 0.0,
                "hallucination_penalty": 0.0,
                "explanation": completion,
                "cwe": "NONE",
            }
        )

    if not rows:
        rows.append(
            {
                "sample_id": "fallback-0",
                "model_version": model_name,
                "true_behavior": "benign",
                "pred_behavior": "benign",
                "malware_score": 1.0,
                "vuln_f1": 0.0,
                "hallucination_penalty": 0.0,
                "explanation": "",
                "cwe": "NONE",
            }
        )

    out_csv = out_dir / "latest_run.csv"
    pd.DataFrame(rows).to_csv(out_csv, index=False)
    print(f"Wrote {out_csv} with {len(rows)} row(s) from {latest_log.name}")


if __name__ == "__main__":
    main()
