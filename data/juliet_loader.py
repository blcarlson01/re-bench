import pandas as pd

def load_juliet(path="data/datasets/juliet/juliet.csv"):
    try:
        df = pd.read_csv(path, encoding="utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"Juliet dataset not found at '{path}'. Run scripts/process_juliet.py first.")
    df = df[["filename", "source", "cwe"]]
    df = df.rename(columns={
        "filename": "sample_id",
        "source": "code",
    })
    return df