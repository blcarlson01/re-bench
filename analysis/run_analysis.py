from pathlib import Path
import argparse
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

try:
    from analysis.load_results import load_latest_run
    from analysis.compute_metrics import compute_cwe_matrix, compute_behavior_confusion, compute_rubric_scores
    from analysis.hallucination_taxonomy import summarize_hallucinations
    from analysis.plots import plot_cwe_heatmap, plot_behavior_confusion, plot_hallucination_taxonomy
except ModuleNotFoundError:
    from load_results import load_latest_run
    from compute_metrics import compute_cwe_matrix, compute_behavior_confusion, compute_rubric_scores
    from hallucination_taxonomy import summarize_hallucinations
    from plots import plot_cwe_heatmap, plot_behavior_confusion, plot_hallucination_taxonomy


def _choose_score_column(df):
    for candidate in ("vuln_f1", "malware_score", "score"):
        if candidate in df.columns:
            return candidate
    raise ValueError("No score column found. Expected one of: vuln_f1, malware_score, score")


def _plot_time_series_regression(df, score_column):
    if "model_version" not in df.columns:
        raise ValueError("Missing required column: model_version")

    model_codes, model_labels = np.unique(df["model_version"].astype(str), return_inverse=True)
    x = model_labels.astype(float)
    y = df[score_column].astype(float).to_numpy()

    order = np.argsort(x)
    x_sorted = x[order]
    y_sorted = y[order]

    plt.figure()
    plt.plot(x_sorted, y_sorted, marker="o", linestyle="-", alpha=0.8, label="Score")

    if len(set(x_sorted)) >= 2:
        slope, intercept = np.polyfit(x_sorted, y_sorted, 1)
        trend = slope * x_sorted + intercept
        plt.plot(x_sorted, trend, linestyle="--", label="Regression")

    tick_positions = np.arange(len(model_codes))
    plt.xticks(tick_positions, model_codes, rotation=45)
    plt.xlabel("model_version")
    plt.ylabel(score_column)
    plt.title("Time-Series Regression: model_version vs score")
    plt.legend()
    plt.tight_layout()
    plt.close()


def run_analysis(csv_path=None):
    try:
        if csv_path:
            df = pd.read_csv(Path(csv_path))
        else:
            df = load_latest_run()
    except FileNotFoundError as exc:
        print(str(exc))
        print("Run an evaluation first, e.g.: inspect eval configs/bigvul.yaml")
        return {
            "rows": 0,
            "score_column": None,
            "cwe_shape": (0, 0),
            "confusion_shape": (0, 0),
            "rubric_scores": {},
        }

    score_column = _choose_score_column(df)
    cwe_matrix = compute_cwe_matrix(df)
    behavior_confusion = compute_behavior_confusion(df)
    hallucination_summary = summarize_hallucinations(df)
    rubric_scores = compute_rubric_scores(df)

    plot_cwe_heatmap(cwe_matrix)
    plot_behavior_confusion(behavior_confusion)
    plot_hallucination_taxonomy(hallucination_summary)
    _plot_time_series_regression(df, score_column)
    plt.show()

    return {
        "rows": len(df),
        "score_column": score_column,
        "cwe_shape": cwe_matrix.shape,
        "confusion_shape": behavior_confusion.shape,
        "rubric_scores": rubric_scores,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run RE-Bench analysis pipeline")
    parser.add_argument("--csv", default=None, help="Optional path to results CSV")
    args = parser.parse_args()
    run_analysis(args.csv)
