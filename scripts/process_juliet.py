import os, csv
from pathlib import Path

BASE = "data/datasets/juliet/"
OUTPUT = "data/datasets/juliet/juliet.csv"

def find_files():
    files = []
    for root, _, fs in os.walk(BASE):
        for f in fs:
            if f.endswith(".c"):
                files.append(os.path.join(root, f))
    return files

with open(OUTPUT, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["filename", "source", "cwe"])
    for file in find_files():
        with open(file) as src:
            code = src.read()
            # Extract CWE from path, e.g., CWE121 or CWE690
            cwe = "NONE"
            parts = file.split(os.sep)
            for p in parts:
                if p.startswith("CWE"):
                    cwe = p
                    break
            writer.writerow([os.path.basename(file), code, cwe])