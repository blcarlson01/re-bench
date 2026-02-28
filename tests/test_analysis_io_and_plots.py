import json
import time

import pandas as pd

from analysis.hallucination_taxonomy import classify_hallucination, summarize_hallucinations
from analysis.load_results import load_latest_run
from analysis.phoenix_to_df import phoenix_events_to_df
from analysis.plots import plot_behavior_confusion, plot_cwe_heatmap, plot_hallucination_taxonomy


def test_load_latest_run_prefers_latest_file(tmp_path):
    older = tmp_path / "a.csv"
    newer = tmp_path / "b.csv"
    pd.DataFrame([{"x": 1}]).to_csv(older, index=False)
    time.sleep(0.01)
    pd.DataFrame([{"x": 2}]).to_csv(newer, index=False)
    df = load_latest_run(str(tmp_path))
    assert int(df.iloc[0]["x"]) == 2


def test_load_latest_run_no_files_raises(tmp_path):
    try:
        load_latest_run(str(tmp_path))
    except FileNotFoundError:
        assert True
    else:
        assert False


def test_hallucination_taxonomy_functions():
    assert classify_hallucination("syscall appears") == "imagined_syscall"
    assert classify_hallucination("reg\\KEY") == "nonexistent_registry"
    assert classify_hallucination("CreateRemoteThread") == "invented_api"
    assert classify_hallucination("clean") == "unknown"

    df = pd.DataFrame({"explanation": ["syscall", "reg\\X", "foo"]})
    out = summarize_hallucinations(df)
    assert set(out.columns) == {"type", "count"}


def test_phoenix_events_to_df(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"a": 1}) + "\ninvalid\n" + json.dumps({"b": 2}), encoding="utf-8")
    df = phoenix_events_to_df(path)
    assert len(df) == 2


def test_plots_handle_empty(monkeypatch):
    called = {"show": 0}

    def fake_show():
        called["show"] += 1

    monkeypatch.setattr("matplotlib.pyplot.show", fake_show)
    plot_cwe_heatmap(pd.DataFrame())
    plot_behavior_confusion(pd.DataFrame())
    plot_hallucination_taxonomy(pd.DataFrame())
    assert called["show"] == 0
