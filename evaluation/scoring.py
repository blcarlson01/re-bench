"""evaluation/scoring.py — MalwareBench benchmark evaluation pipeline.

Implements the full evaluation pipeline from the bench_score spec:

    model inference  →  prediction normalization  →  metric computation  →  benchmark report

Usage:
    python evaluation/scoring.py \\
        --predictions predictions.jsonl \\
        --tasks tasks/ \\
        --output results.json

Input format (JSONL):
    {"id": "big15_assembly_1023", "prediction": "T1055 Process Injection"}

Output format:
    {
        "assembly_understanding": 0.74,
        "capability_extraction": 0.68,
        "mitre_mapping": 0.71,
        "family_classification": 0.82,
        "behavior_explanation": 0.70,
        "benchmark_score": 0.73
    }

Task-to-metric mapping (per spec):
    mitre_mapping         → accuracy (after MITRE normalization)
    family_classification → accuracy (after family normalization)
    capability_extraction → F1 (macro, multi-label aware)
    assembly_understanding → LLM judge rubric score (normalized to [0, 1])
    behavior_explanation  → LLM judge rubric score (normalized to [0, 1])
"""

import argparse
import json
import re
from pathlib import Path

from scorers.accuracy_scorer import AccuracyScorer, TopKAccuracyScorer
from scorers.llm_judge_scorer import LLMJudgeScorer
from scorers.prediction_normalizer import (
    normalize_capability,
    normalize_family,
    normalize_mitre,
    normalize_prediction,
)

# ---------------------------------------------------------------------------
# Task-type → metric mapping
# ---------------------------------------------------------------------------

#: Tasks evaluated with exact-match accuracy after normalization
_ACCURACY_TASKS = {
    "mitre_mapping": "mitre_mapping",
    "family_classification": "family_classification",
}

#: Tasks evaluated with macro-F1 (multi-label capable)
_F1_TASKS = {"capability_extraction"}

#: Tasks evaluated with the LLM judge rubric (0–3, normalized to [0, 1])
_JUDGE_TASKS = {"behavior_explanation", "assembly_understanding"}


# ---------------------------------------------------------------------------
# Prediction normalization
# ---------------------------------------------------------------------------

def normalize(prediction: str, task_type: str) -> str:
    """Apply the appropriate normalization for *task_type*."""
    if task_type == "mitre_mapping":
        return normalize_mitre(prediction)
    if task_type == "family_classification":
        return normalize_family(prediction)
    if task_type == "capability_extraction":
        return normalize_capability(prediction)
    return normalize_prediction(prediction)


# ---------------------------------------------------------------------------
# Per-task scorers
# ---------------------------------------------------------------------------

def _accuracy(pred: str, ref: str, task_type: str) -> float:
    p = normalize(pred, task_type)
    r = normalize(ref, task_type)
    return 1.0 if p == r else 0.0


def _f1_single(pred: str, ref: str, task_type: str) -> float:
    """F1 for a single prediction/reference pair (binary subset matching)."""
    p = normalize(pred, task_type)
    r = normalize(ref, task_type)
    # Tokenise for partial-credit on multi-label strings
    pred_set = set(re.split(r"[,;|]+", p))
    ref_set = set(re.split(r"[,;|]+", r))
    tp = len(pred_set & ref_set)
    precision = tp / len(pred_set) if pred_set else 0.0
    recall = tp / len(ref_set) if ref_set else 0.0
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def _judge(pred: str, task_prompt: str, ref: str) -> float:
    """Rubric score normalized to [0, 1]."""
    scorer = LLMJudgeScorer()
    raw = scorer._heuristic_rubric(pred, ref)
    return LLMJudgeScorer.normalize_to_unit(raw)


# ---------------------------------------------------------------------------
# Ground-truth loader
# ---------------------------------------------------------------------------

def load_tasks(tasks_dir: str) -> dict[str, dict]:
    """Load all JSONL task files from *tasks_dir*.

    Returns mapping: sample_id → {"answer": ..., "task": ..., "input": ...}.
    """
    ground_truth: dict[str, dict] = {}
    for path in Path(tasks_dir).glob("*.jsonl"):
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sid = str(rec.get("id", ""))
                if sid:
                    ground_truth[sid] = rec
    return ground_truth


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def evaluate(
    predictions_path: str,
    tasks_dir: str,
    output_path: str,
) -> dict[str, float]:
    """Run the full evaluation pipeline and return the report dict."""

    # Load ground truth
    ground_truth = load_tasks(tasks_dir)

    # Load predictions
    predictions: list[dict] = []
    with open(predictions_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                predictions.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Accumulate per-task scores
    task_scores: dict[str, list[float]] = {
        "assembly_understanding": [],
        "capability_extraction": [],
        "mitre_mapping": [],
        "family_classification": [],
        "behavior_explanation": [],
    }

    for pred_rec in predictions:
        sid = str(pred_rec.get("id", ""))
        prediction = str(pred_rec.get("prediction", ""))
        if not sid or sid not in ground_truth:
            continue

        gt = ground_truth[sid]
        task_type = str(gt.get("task", ""))
        reference = str(gt.get("answer", ""))
        task_prompt = str(gt.get("input", ""))

        if task_type in _ACCURACY_TASKS:
            score = _accuracy(prediction, reference, task_type)
            task_scores[task_type].append(score)

        elif task_type in _F1_TASKS:
            score = _f1_single(prediction, reference, task_type)
            task_scores[task_type].append(score)

        elif task_type in _JUDGE_TASKS:
            score = _judge(prediction, task_prompt, reference)
            task_scores[task_type].append(score)

    # Aggregate per-task means
    report: dict[str, float] = {}
    for task_type, scores in task_scores.items():
        report[task_type] = round(sum(scores) / len(scores), 4) if scores else 0.0

    # Overall benchmark score = mean of non-zero task scores (spec: mean of normalized scores)
    active = [v for v in report.values() if v > 0.0]
    report["benchmark_score"] = round(sum(active) / len(active), 4) if active else 0.0

    # Write output
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="MalwareBench benchmark evaluation pipeline."
    )
    parser.add_argument(
        "--predictions",
        required=True,
        metavar="FILE",
        help="JSONL file of model predictions: {id, prediction}.",
    )
    parser.add_argument(
        "--tasks",
        required=True,
        metavar="DIR",
        help="Directory containing ground-truth JSONL task files.",
    )
    parser.add_argument(
        "--output",
        default="results.json",
        metavar="FILE",
        help="Path to write the JSON report (default: results.json).",
    )
    args = parser.parse_args()

    report = evaluate(args.predictions, args.tasks, args.output)

    print("\nBenchmark Report")
    print("=" * 40)
    for task_type, score in report.items():
        label = task_type.replace("_", " ").title()
        print(f"  {label:<30} {score:.4f}")
    print("=" * 40)


if __name__ == "__main__":
    main()
