import requests, gzip, json, csv
from pathlib import Path

EMBER_URLS = {
    "2017": "https://ember.elastic.co/ember_dataset.tar.bz2",
    "2017_2": "https://ember.elastic.co/ember_dataset_2017_2.tar.bz2",
    "2018_2": "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
}

def download(url, out_path):
    r = requests.get(url, stream=True)
    with open(out_path, "wb") as f:
        for chunk in r.iter_content(1024):
            f.write(chunk)

def extract_jsonl_to_csv(jsonl_path, csv_out):
    out_fields = ["sha256", "label"]
    with open(csv_out, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=out_fields)
        writer.writeheader()
        with open(jsonl_path, "rt") as f:
            for line in f:
                obj = json.loads(line)
                writer.writerow({"sha256":obj["sha256"], "label":obj["label"]})

if __name__ == "__main__":
    Path("data/datasets/ember").mkdir(parents=True, exist_ok=True)
    py = "ember2017.jsonl"
    # Example: download the 2017 release
    download(EMBER_URLS["2017"], "ember2017.tar.bz2")
    # You must manually extract the JSONL file after download
    # Then:
    extract_jsonl_to_csv("ember2017.jsonl", "data/datasets/ember/ember.csv")