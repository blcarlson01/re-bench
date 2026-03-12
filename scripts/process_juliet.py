import csv
import os

BASE = "data/datasets/juliet/"
OUTPUT = "data/datasets/juliet/juliet.csv"


def find_files(base=BASE):
    files = []
    for root, _, fs in os.walk(base):
        for file_name in fs:
            if file_name.endswith(".c"):
                files.append(os.path.join(root, file_name))
    return files


def extract_cwe_from_path(file_path):
    parts = file_path.split(os.sep)
    for part in parts:
        if part.startswith("CWE"):
            return part
    return "NONE"


def process_juliet(base=BASE, output=OUTPUT):
    with open(output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["filename", "source", "cwe"])

        for file_path in find_files(base):
            with open(file_path, encoding="utf-8") as src:
                code = src.read()
            cwe = extract_cwe_from_path(file_path)
            writer.writerow([os.path.basename(file_path), code, cwe])


if __name__ == "__main__":
    process_juliet()