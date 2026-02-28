import csv
import gzip
import json
from types import SimpleNamespace

import pandas as pd

from dashboard.app import build_dashboard_figure
from run_eval import evaluate
from scripts.csv_to_rebench import csv_to_jsonl
from scripts.fetch_ember import download, extract_jsonl_to_csv
from scripts.fetch_malwarebazaar import fetch_all, write_csv
from scripts.fetch_nvd_cve import fetch_year, parse_to_csv
from scripts.process_juliet import extract_cwe_from_path, find_files, process_juliet
from tracing.phoenix_logger import PhoenixTraceLogger


def test_csv_to_jsonl(tmp_path):
    source = tmp_path / "a.csv"
    out = tmp_path / "a.jsonl"
    pd.DataFrame([{"sha": "x", "lab": "y"}]).to_csv(source, index=False)
    csv_to_jsonl(source, out, {"sha256": "sha", "true_behavior": "lab"})
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["sha256"] == "x"


def test_fetch_ember_helpers(tmp_path, monkeypatch):
    target = tmp_path / "download.bin"

    class FakeResp:
        @staticmethod
        def iter_content(_):
            yield b"abc"

    monkeypatch.setattr("scripts.fetch_ember.requests.get", lambda *a, **k: FakeResp())
    download("http://x", target)
    assert target.read_bytes() == b"abc"

    jsonl = tmp_path / "a.jsonl"
    out_csv = tmp_path / "o.csv"
    jsonl.write_text(json.dumps({"sha256": "s", "label": 1}) + "\n", encoding="utf-8")
    extract_jsonl_to_csv(jsonl, out_csv)
    assert "sha256" in pd.read_csv(out_csv).columns


def test_fetch_malwarebazaar_helpers(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scripts.fetch_malwarebazaar.requests.post",
        lambda *a, **k: SimpleNamespace(json=lambda: {"data": [{"sha256_hash": "x", "signature": "fam", "file_type": "exe"}]}),
    )
    data = fetch_all()
    assert len(data) == 1

    output = tmp_path / "m.csv"
    monkeypatch.setattr("scripts.fetch_malwarebazaar.OUTPUT", str(output))
    write_csv(data)
    assert output.exists()


def test_fetch_nvd_helpers(tmp_path, monkeypatch):
    sample = {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-1"},
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                }
            }
        ]
    }
    gz = tmp_path / "x.json.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as f:
        json.dump(sample, f)

    output = tmp_path / "nvd.csv"
    monkeypatch.setattr("scripts.fetch_nvd_cve.OUTCSV", str(output))
    with output.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["cve_id", "cwes"])
    parse_to_csv(str(gz))
    rows = pd.read_csv(output)
    assert len(rows) == 1

    monkeypatch.setattr(
        "scripts.fetch_nvd_cve.requests.get",
        lambda url: SimpleNamespace(content=b"abc"),
    )
    monkeypatch.chdir(tmp_path)
    path = fetch_year("2024")
    assert (tmp_path / path).exists()


def test_process_juliet_helpers(tmp_path):
    base = tmp_path / "juliet" / "CWE121" / "sub"
    base.mkdir(parents=True)
    source = base / "a.c"
    source.write_text("int main(){}", encoding="utf-8")

    files = find_files(tmp_path / "juliet")
    assert len(files) == 1
    assert extract_cwe_from_path(str(source)) == "CWE121"

    output = tmp_path / "out.csv"
    process_juliet(base=str(tmp_path / "juliet"), output=str(output))
    assert output.exists()


def test_dashboard_build_figure(tmp_path):
    csv_path = tmp_path / "latest_run.csv"
    pd.DataFrame(
        {
            "malware_score": [1.0],
            "vuln_f1": [0.5],
            "model_version": ["m1"],
        }
    ).to_csv(csv_path, index=False)
    fig = build_dashboard_figure(str(csv_path))
    assert fig is not None


def test_phoenix_logger(monkeypatch):
    class FakeSpan:
        def __init__(self):
            self.logged = None

        def log(self, data):
            self.logged = data

        def end(self):
            self.ended = True

    span = FakeSpan()
    monkeypatch.setattr(
        "tracing.phoenix_logger.px",
        SimpleNamespace(start_span=lambda name: span, launch_app=lambda: None),
    )
    logger = PhoenixTraceLogger()
    logger.log(SimpleNamespace(to_dict=lambda: {"x": 1}))
    assert span.logged == {"x": 1}


def test_run_eval_evaluate(tmp_path):
    task_path = tmp_path / "task.yaml"
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    output_csv = tmp_path / "results" / "latest.csv"

    task_path.write_text("question: 'Q: {imports}'\n", encoding="utf-8")
    (samples_dir / "s1.json").write_text(
        json.dumps({"id": "1", "imports": "A", "reference": {"true_behavior": "malware"}}),
        encoding="utf-8",
    )

    def model(prompt):
        return {"pred_behavior": "malware", "explanation": "A"}

    result = evaluate(model=model, task_path=str(task_path), samples_dir=str(samples_dir), output_csv=str(output_csv))
    assert result["rows"] == 1
    assert output_csv.exists()
