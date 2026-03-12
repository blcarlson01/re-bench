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


def test_task_factories_return_task_objects():
    """Verify all task factories are importable and return proper Task objects.

    Replaces the legacy hallucination-logging branch test, which relied on
    the removed ``sample.model()`` call pattern.
    """
    from inspect_ai import Task
    from tasks.bigvul_task import bigvul_task
    from tasks.juliet_task import juliet_task
    from tasks.malwarebazaar_task import malwarebazaar_task

    for factory in (bigvul_task, juliet_task, malwarebazaar_task):
        result = factory()
        assert isinstance(result, Task)
        assert len(result.dataset) >= 1
        assert result.scorer is not None


def test_tracing_branches(monkeypatch):
    monkeypatch.setattr("tracing.phoenix_logger.px", None)
    launch_phoenix_app()
    PhoenixTraceLogger().log(SimpleNamespace(to_dict=lambda: {"x": 1}))
