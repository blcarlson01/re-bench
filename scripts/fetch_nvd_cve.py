import requests, gzip, json, csv
from pathlib import Path

BASE = "https://nvd.nist.gov/feeds/json/cve/1.0/"
YEARS = ["2024", "2023"]
OUTCSV = "data/datasets/bigvul/nvd_cve.csv"

def fetch_year(year):
    url = f"{BASE}nvdcve-1.0-{year}.json.gz"
    r = requests.get(url)
    gz_path = f"{year}.json.gz"
    with open(gz_path, "wb") as f:
        f.write(r.content)
    return gz_path

def parse_to_csv(gz_file):
    with gzip.open(gz_file, "rt", encoding="utf-8") as f:
        data = json.load(f)
    with open(OUTCSV, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        for item in data["CVE_Items"]:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            cwes = []
            weaknesses = item["cve"]["weaknesses"] or []
            for w in weaknesses:
                for d in w["description"]:
                    if d["value"].startswith("CWE"):
                        cwes.append(d["value"])
            writer.writerow([cve_id, "|".join(set(cwes))])

if __name__ == "__main__":
    Path("data/datasets/bigvul").mkdir(parents=True, exist_ok=True)
    with open(OUTCSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["cve_id", "cwes"])
    for y in YEARS:
        gz = fetch_year(y)
        parse_to_csv(gz)