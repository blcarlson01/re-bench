import pandas as pd

from analysis.compute_metrics import (
    _macro_f1_for_columns,
    compute_behavior_confusion,
    compute_cwe_matrix,
    compute_rubric_scores,
)


def test_macro_f1_missing_columns_returns_none():
    df = pd.DataFrame({"a": [1]})
    assert _macro_f1_for_columns(df, "x", "y") is None


def test_compute_cwe_matrix_and_confusion():
    df = pd.DataFrame(
        {
            "model_version": ["m1", "m1", "m2"],
            "cwe": ["CWE-79", "CWE-79", "CWE-89"],
            "vuln_f1": [1.0, 0.0, 0.5],
            "true_behavior": ["malware", "benign", "malware"],
            "pred_behavior": ["malware", "malware", "benign"],
        }
    )
    cwe = compute_cwe_matrix(df)
    conf = compute_behavior_confusion(df)
    assert not cwe.empty
    assert not conf.empty


def test_compute_rubric_scores_default_and_weighted():
    df = pd.DataFrame(
        {
            "true_behavior": ["malware", "benign"],
            "pred_behavior": ["malware", "benign"],
            "true_cwe": ["CWE-79", "CWE-89"],
            "pred_cwe": ["CWE-79", "CWE-999"],
            "explanation_similarity": [0.8, 0.9],
            "hallucination_score": [0.7, 0.9],
        }
    )

    result = compute_rubric_scores(df)
    assert result["malware_f1"] is not None
    assert result["cwe_f1"] is not None
    assert result["composite_score"] is not None

    result_custom = compute_rubric_scores(df, weights={"malware_f1": 1.0})
    assert result_custom["composite_score"] == result_custom["malware_f1"]
