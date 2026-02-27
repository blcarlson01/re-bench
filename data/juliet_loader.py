import pandas as pd

def load_juliet(path="data/datasets/juliet/juliet.csv"):
    df = pd.read_csv(path)
    df = df[["filename", "source", "cwe"]]
    df = df.rename(columns={
        "filename": "sample_id",
        "source": "code",
        "cwe": "cwe"
    })
    return df