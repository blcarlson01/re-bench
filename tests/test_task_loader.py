import json

from loaders.task_loader import load_samples, load_task_yaml


def test_load_task_yaml(tmp_path):
    path = tmp_path / "task.yaml"
    path.write_text("name: test\nvalue: 1\n", encoding="utf-8")
    data = load_task_yaml(path)
    assert data["name"] == "test"


def test_load_samples(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"id": 1}), encoding="utf-8")
    b.write_text(json.dumps({"id": 2}), encoding="utf-8")
    rows = load_samples(tmp_path)
    assert len(rows) == 2
