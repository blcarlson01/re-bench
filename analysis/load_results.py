import pandas as pd
from pathlib import Path

def load_latest_run(results_dir="results/runs"):
    base = Path(results_dir)
    path = base / "latest_run.csv"
    if not path.exists():
        candidates = sorted(base.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise FileNotFoundError(f"No CSV results found in {base}")
        path = candidates[0]
    return pd.read_csv(path)