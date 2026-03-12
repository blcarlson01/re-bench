import pandas as pd
import json

'''
csv_to_jsonl(
    "data/datasets/ember/ember.csv",
    "data/datasets/ember/ember_task.jsonl",
    {"sha256":"sha256", "label":"true_behavior"}
)
'''
def csv_to_jsonl(csv_path, jsonl_path, mapping):
    df = pd.read_csv(csv_path)
    with open(jsonl_path, "w", encoding="utf-8") as out:
        for _, row in df.iterrows():
            obj = {k: row[v] for k, v in mapping.items()}
            out.write(json.dumps(obj) + "\n")