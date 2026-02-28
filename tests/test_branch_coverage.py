import json
import sys
import importlib
from types import SimpleNamespace

import pandas as pd
import pytest

from analysis.compute_metrics import _macro_f1_for_columns, compute_cwe_matrix, compute_rubric_scores
from analysis.hallucination_taxonomy import summarize_hallucinations
from analysis.phoenix_to_df import phoenix_events_to_df
from analysis.run_analysis import _plot_time_series_regression, run_analysis
from dashboard.app import main as dashboard_main
from scorers.hallucination_scorer import HallucinationScorer
from scorers.malware_scorer import MalwareBehaviorScorer
from scorers.vuln_f1_scorer import VulnF1Scorer
from tracing.phoenix_logger import PhoenixTraceLogger, launch_phoenix_app


def test_compute_metrics_extra_branches():
    empty_df = pd.DataFrame({"true": [], "pred": []})
    assert _macro_f1_for_columns(empty_df, "true", "pred") is None

    assert compute_cwe_matrix(pd.DataFrame({"x": [1]})).empty

    result = compute_rubric_scores(pd.DataFrame({"x": [1]}), weights={"malware_f1": 0.0})
    assert result["composite_score"] is None


def test_hallucination_taxonomy_missing_col():
    out = summarize_hallucinations(pd.DataFrame({"x": [1]}))
    assert list(out.columns) == ["type", "count"]


def test_phoenix_to_df_missing_and_empty_lines(tmp_path):
    assert phoenix_events_to_df(tmp_path / "missing.jsonl").empty
    path = tmp_path / "events.jsonl"
    path.write_text("\n" + json.dumps({"ok": 1}) + "\n", encoding="utf-8")
    out = phoenix_events_to_df(path)
    assert len(out) == 1


def test_run_analysis_other_branches(monkeypatch):
    with pytest.raises(ValueError):
        _plot_time_series_regression(pd.DataFrame({"x": [1]}), "x")

    monkeypatch.setattr("analysis.run_analysis.load_latest_run", lambda: pd.DataFrame({"score": [1]}))
    with pytest.raises(ValueError):
        run_analysis()


def test_dashboard_main(monkeypatch):
    fig = SimpleNamespace(show=lambda: None)
    monkeypatch.setattr("dashboard.app.build_dashboard_figure", lambda csv_path: fig)
    dashboard_main("dummy.csv")


def test_scorer_edge_branches():
    hall = HallucinationScorer()
    assert hall.score({"explanation": "123"}, {}) == 1.0

    mal = MalwareBehaviorScorer()
    assert mal.score({"pred_behavior": ""}, {"true_behavior": "x"}) == 0.0
    assert mal.macro_f1([], []) == 0.0

    vuln = VulnF1Scorer()
    assert vuln.macro_f1([], []) == 0.0


def test_task_hallucination_branches(monkeypatch):
    inspect_module = SimpleNamespace(task=lambda fn: fn)
    scorer_module = SimpleNamespace(accuracy=object())
    phoenix_module = SimpleNamespace()
    phoenix_trace = SimpleNamespace(log_event=lambda *a, **k: None)

    monkeypatch.setitem(sys.modules, "inspect_ai", inspect_module)
    monkeypatch.setitem(sys.modules, "inspect_ai.scorer", scorer_module)
    monkeypatch.setitem(sys.modules, "phoenix", phoenix_module)
    monkeypatch.setitem(sys.modules, "phoenix.trace", phoenix_trace)

    for module_name in ("tasks.bigvul_task", "tasks.juliet_task", "tasks.malwarebazaar_task"):
        if module_name in sys.modules:
            del sys.modules[module_name]

    bigvul = importlib.import_module("tasks.bigvul_task")
    juliet = importlib.import_module("tasks.juliet_task")
    malware = importlib.import_module("tasks.malwarebazaar_task")

    calls = []
    monkeypatch.setattr(bigvul, "log_event", lambda *a, **k: calls.append(("bigvul", a, k)))
    monkeypatch.setattr(juliet, "log_event", lambda *a, **k: calls.append(("juliet", a, k)))
    monkeypatch.setattr(malware, "log_event", lambda *a, **k: calls.append(("malware", a, k)))

    class Fake(dict):
        def model(self, prompt):
            if "vulnerability researcher" in prompt:
                return "imaginary_function CWE-79"
            if "Analyze the code" in prompt:
                return "syscall CWE-79"
            return "reg\\SOFTWARE\\FAKEKEY encrypt"

    bigvul.bigvul_task(Fake({"code": "x", "cwe": "CWE-79"}))
    juliet.juliet_task(Fake({"code": "int main(){}", "cwe": "CWE-79"}))
    malware.malwarebazaar_task(Fake({"family": "fam", "file_type": "exe"}))

    assert len(calls) == 3


def test_tracing_branches(monkeypatch):
    monkeypatch.setattr("tracing.phoenix_logger.px", None)
    launch_phoenix_app()
    PhoenixTraceLogger().log(SimpleNamespace(to_dict=lambda: {"x": 1}))
