import pandas as pd
import json

def load_ember(path="data/datasets/ember/ember.json"):
    with open(path) as f:
        data = [json.loads(line) for line in f]

    df = pd.DataFrame(data)
    df = df[["sha256", "label"]]
    df["true_behavior"] = df["label"].map({1: "malware", 0: "benign"})
    return df