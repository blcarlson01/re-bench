import pandas as pd

def load_bigvul(path="data/datasets/bigvul/bigvul.csv"):
    try:
        df = pd.read_csv(path, encoding="utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"BigVul dataset not found at '{path}'. Run scripts/fetch_nvd_cve.py first.")
    df = df[["id", "func", "cwe"]]
    df = df.rename(columns={
        "id": "sample_id",
        "func": "code",
    })
    return df