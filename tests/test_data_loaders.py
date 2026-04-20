import json

import pandas as pd

from data.bigvul_loader import load_bigvul
from data.ember_loader import load_ember
from data.juliet_loader import load_juliet
from data.malwarebazaar_loader import load_malwarebazaar
from data.sorel_loader import load_sorel


def test_load_ember(tmp_path):
    data_path = tmp_path / "ember.json"
    rows = [
        {"sha256": "a", "label": 1},
        {"sha256": "b", "label": 0},
    ]
    data_path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    df = load_ember(str(data_path))

    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == ["sha256", "label", "true_behavior"]
    assert set(df["true_behavior"].tolist()) == {"malware", "benign"}


def test_load_bigvul(tmp_path):
    data_path = tmp_path / "bigvul.csv"
    pd.DataFrame([{"id": 1, "func": "int main(){}", "cwe": "CWE-79"}]).to_csv(data_path, index=False)
    df = load_bigvul(str(data_path))
    assert list(df.columns) == ["sample_id", "code", "cwe"]


def test_load_juliet(tmp_path):
    data_path = tmp_path / "juliet.csv"
    pd.DataFrame([{"filename": "a.c", "source": "code", "cwe": "CWE-120"}]).to_csv(data_path, index=False)
    df = load_juliet(str(data_path))
    assert list(df.columns) == ["sample_id", "code", "cwe"]


def test_load_malwarebazaar(tmp_path):
    data_path = tmp_path / "meta.csv"
    pd.DataFrame([
        {"sha256_hash": "x", "signature": "fam", "file_type": "exe", "imphash": "h"}
    ]).to_csv(data_path, index=False)
    df = load_malwarebazaar(str(data_path))
    assert list(df.columns) == ["sample_id", "family", "file_type", "imphash"]


def test_load_sorel(tmp_path):
    data_path = tmp_path / "sorel.jsonl"
    records = [
        {
            "id": "abc123",
            "dataset": "sorel",
            "artifact_type": "pe_metadata",
            "task": "behavior_tag_prediction",
            "input": "PE Imports:\n  KERNEL32.dll: CreateFileW\nSection Names: .text\nStrings: .onion",
            "answer": "ransomware",
            "first_seen": 1577836800,
            "time_period": "2020-H1",
        },
        {
            "id": "def456",
            "dataset": "sorel",
            "artifact_type": "pe_metadata",
            "task": "behavior_tag_prediction",
            "input": "PE Imports:\n  WS2_32.dll: socket, connect\nSection Names: .text\nStrings: cmd.exe",
            "answer": "trojan",
            "first_seen": 1546300800,
            "time_period": "2019-H1",
        },
    ]
    data_path.write_text(
        "\n".join(json.dumps(r) for r in records), encoding="utf-8"
    )

    df = load_sorel(str(data_path))

    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == ["sample_id", "tag", "first_seen", "time_period"]
    assert len(df) == 2
    assert set(df["tag"].tolist()) == {"ransomware", "trojan"}
    assert df["time_period"].tolist() == ["2020-H1", "2019-H1"]
