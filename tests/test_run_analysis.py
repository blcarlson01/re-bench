import pandas as pd

from analysis.run_analysis import _choose_score_column, run_analysis


def test_choose_score_column():
    assert _choose_score_column(pd.DataFrame({"score": [1]})) == "score"


def test_choose_score_column_raises():
    try:
        _choose_score_column(pd.DataFrame({"x": [1]}))
    except ValueError:
        assert True
    else:
        assert False


def test_run_analysis_with_csv(tmp_path, monkeypatch):
    path = tmp_path / "r.csv"
    pd.DataFrame(
        {
            "model_version": ["m1", "m2"],
            "cwe": ["CWE-79", "CWE-89"],
            "vuln_f1": [0.2, 0.8],
            "true_behavior": ["malware", "benign"],
            "pred_behavior": ["malware", "benign"],
            "true_cwe": ["CWE-79", "CWE-89"],
            "pred_cwe": ["CWE-79", "CWE-89"],
            "explanation": ["a", "b"],
            "hallucination_score": [0.9, 1.0],
        }
    ).to_csv(path, index=False)

    monkeypatch.setattr("matplotlib.pyplot.show", lambda: None)
    result = run_analysis(str(path))
    assert result["rows"] == 2
    assert result["score_column"] == "vuln_f1"


def test_run_analysis_missing_file_returns_empty():
    result = run_analysis("nonexistent_file.csv")
    assert result["rows"] == 0
