import csv
import gzip
import json
from types import SimpleNamespace

import pandas as pd

from dashboard.app import build_dashboard_figure
from run_eval import evaluate
from scripts.csv_to_rebench import csv_to_jsonl
from scripts.fetch_bigvul import generate_sample_dataset as bigvul_generate_sample, download_bigvul
from scripts.fetch_ember import download, extract_jsonl_from_tar, generate_sample_dataset as ember_generate_sample
from scripts.fetch_malwarebazaar import fetch_all, generate_sample_dataset as malwarebazaar_generate_sample, write_csv
from scripts.fetch_nvd_cve import fetch_year, parse_to_csv
from scripts.process_juliet import extract_cwe_from_path, find_files, generate_sample_dataset as juliet_generate_sample, process_juliet
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
        headers = {"Content-Length": "3"}

        @staticmethod
        def raise_for_status():
            pass

        @staticmethod
        def iter_content(**kwargs):
            yield b"abc"

    monkeypatch.setattr("scripts.fetch_ember.requests.get", lambda *a, **k: FakeResp())
    download("http://x", target)
    assert target.read_bytes() == b"abc"

    # generate_sample_dataset writes JSONL (sha256 + label) consumed by ember_task.py
    out_jsonl = tmp_path / "ember.json"
    n = ember_generate_sample(n=10, out_jsonl=out_jsonl)
    assert n == 10
    lines = [json.loads(l) for l in out_jsonl.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 10
    assert all("sha256" in l and "label" in l for l in lines)

    # extract_jsonl_from_tar: create a minimal .tar.bz2 containing one .jsonl file
    import gzip as _gzip, tarfile as _tarfile, io as _io
    row = json.dumps({"sha256": "abc123", "label": 1}) + "\n"
    buf = _io.BytesIO(row.encode())
    tar_buf = _io.BytesIO()
    with _tarfile.open(fileobj=tar_buf, mode="w:bz2") as tf:
        info = _tarfile.TarInfo(name="ember_train.jsonl")
        info.size = len(row)
        tf.addfile(info, buf)
    tar_path = tmp_path / "ember.tar.bz2"
    tar_path.write_bytes(tar_buf.getvalue())
    out2 = tmp_path / "out.json"
    count = extract_jsonl_from_tar(tar_path, out2)
    assert count == 1
    assert json.loads(out2.read_text(encoding="utf-8"))["sha256"] == "abc123"


def test_fetch_malwarebazaar_helpers(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scripts.fetch_malwarebazaar.requests.post",
        lambda *a, **k: SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"data": [{"sha256_hash": "x", "signature": "fam", "file_type": "exe", "imphash": ""}]},
        ),
    )
    data = fetch_all()
    assert len(data) == 1

    output = tmp_path / "m.csv"
    monkeypatch.setattr("scripts.fetch_malwarebazaar.OUTPUT", str(output))
    write_csv(data)
    assert output.exists()
    rows = list(csv.DictReader(output.open(encoding="utf-8")))
    assert rows[0]["sha256_hash"] == "x"
    assert rows[0]["signature"] == "fam"


def test_fetch_malwarebazaar_sample(tmp_path):
    out = tmp_path / "metadata.csv"
    n = malwarebazaar_generate_sample(10, str(out))
    assert n == 10
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert len(rows) == 10
    assert all({"sha256_hash", "signature", "file_type", "imphash"} <= set(r.keys()) for r in rows)
    assert all(r["signature"] for r in rows)
    # sha256_hash should look like a 64-char hex string
    assert all(len(r["sha256_hash"]) == 64 for r in rows)


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
        lambda url: SimpleNamespace(content=b"abc", raise_for_status=lambda: None),
    )
    monkeypatch.chdir(tmp_path)
    path = fetch_year("2024")
    assert (tmp_path / path).exists()


def test_fetch_bigvul_sample(tmp_path):
    out = tmp_path / "bigvul.csv"
    n = bigvul_generate_sample(10, str(out))
    assert n == 10
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert len(rows) == 10
    assert all({"id", "func", "cwe"} <= set(r.keys()) for r in rows)
    assert all(r["cwe"].startswith("CWE-") for r in rows)


def test_fetch_bigvul_download(tmp_path, monkeypatch):
    """download_bigvul should stream the CSV and reformat to id/func/cwe."""
    import io
    raw_csv = "Unnamed: 0,func,cwe_id\n0,void foo(){},CWE-119\n1,void bar(){},CWE-78\n"

    class FakeResp:
        headers = {"Content-Length": str(len(raw_csv.encode()))}

        def raise_for_status(self):
            pass

        def iter_content(self, **kwargs):
            yield raw_csv.encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr("scripts.fetch_bigvul.requests.get", lambda *a, **k: FakeResp())
    out = tmp_path / "bigvul.csv"
    count = download_bigvul(str(out))
    assert count == 2
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert [r["cwe"] for r in rows] == ["CWE-119", "CWE-78"]


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

    # generate_sample_dataset produces a CSV usable by juliet_task.py
    sample_out = tmp_path / "sample.csv"
    n = juliet_generate_sample(n=8, output=str(sample_out))
    assert n == 8
    df = pd.read_csv(sample_out)
    assert list(df.columns) == ["filename", "source", "cwe"]
    assert len(df) == 8
    assert df["cwe"].str.startswith("CWE").all()


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
