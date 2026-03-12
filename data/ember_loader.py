import pandas as pd
import json

def load_ember(path="data/datasets/ember/ember.json"):
    try:
        with open(path, encoding="utf-8") as f:
            data = [json.loads(line) for line in f]
    except FileNotFoundError:
        raise FileNotFoundError(f"Ember dataset not found at '{path}'. Run scripts/fetch_ember.py first.")

    df = pd.DataFrame(data)
    df = df[["sha256", "label"]]
    df["true_behavior"] = df["label"].map({1: "malware", 0: "benign"})
    return df