import pandas as pd
from pathlib import Path

def load_latest_run(results_dir="results/runs"):
    path = Path(results_dir) / "latest_run.csv"
    return pd.read_csv(path)