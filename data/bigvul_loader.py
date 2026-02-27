import pandas as pd

def load_bigvul(path="data/datasets/bigvul/bigvul.csv"):
    df = pd.read_csv(path)
    df = df[["id", "func", "cwe"]]
    df = df.rename(columns={
        "id": "sample_id",
        "func": "code",
        "cwe": "cwe"
    })
    return df