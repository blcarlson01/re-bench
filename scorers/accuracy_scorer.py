"""accuracy_scorer.py — accuracy and top-K accuracy scorers.

Implements the objective metrics from the mama_bench_score.md spec:

    accuracy = correct_predictions / total_predictions

Used for:
    mitre_mapping       — prediction normalized via normalize_mitre()
    family_classification — prediction normalized via normalize_family()

Also provides top-K accuracy for optional classification tasks.

Prediction normalization (lowercase, whitespace, MITRE synonym mapping)
is applied before comparison, as required by the spec.
"""

from inspect_ai.scorer import Scorer
from scorers.prediction_normalizer import (
    normalize_family,
    normalize_mitre,
    normalize_prediction,
)


class AccuracyScorer(Scorer):
    """Exact-match accuracy scorer with prediction normalization.

    Parameters
    ----------
    task_type:
        One of ``'mitre_mapping'``, ``'family_classification'``, or ``'default'``.
        Controls which normalization function is applied to both prediction
        and reference before comparison.
    """

    def __init__(self, task_type: str = "default"):
        if task_type not in ("mitre_mapping", "family_classification", "default"):
            raise ValueError(
                f"Unknown task_type '{task_type}'. "
                "Choose from: mitre_mapping, family_classification, default."
            )
        self._task_type = task_type

    def _normalize(self, text: str) -> str:
        if self._task_type == "mitre_mapping":
            return normalize_mitre(text)
        if self._task_type == "family_classification":
            return normalize_family(text)
        return normalize_prediction(text)

    def score(self, output, reference):
        """Return 1.0 if normalized prediction matches normalized reference, else 0.0."""
        prediction = ""
        if isinstance(output, dict):
            prediction = str(output.get("prediction", output.get("completion", "")))
        else:
            prediction = str(output)

        ref_text = ""
        if isinstance(reference, dict):
            ref_text = str(reference.get("answer", reference.get("target", "")))
        else:
            ref_text = str(reference)

        return 1.0 if self._normalize(prediction) == self._normalize(ref_text) else 0.0

    @staticmethod
    def aggregate_accuracy(scores: list[float]) -> float:
        """Compute accuracy = correct / total from a list of 0/1 scores."""
        if not scores:
            return 0.0
        return sum(scores) / len(scores)


class TopKAccuracyScorer(Scorer):
    """Top-K accuracy scorer for classification tasks.

    The model output is expected to contain ``top_k_predictions``: a list of
    candidate labels in decreasing confidence order.  Returns 1.0 if the
    reference label appears in the top-K predictions.

    Parameters
    ----------
    k:
        Number of top predictions to evaluate (default: 3 per spec).
    task_type:
        Normalization mode, same as ``AccuracyScorer``.
    """

    def __init__(self, k: int = 3, task_type: str = "default"):
        self._k = k
        self._accuracy_scorer = AccuracyScorer(task_type=task_type)

    def score(self, output, reference):
        """Return 1.0 if the reference appears in the top-K predictions."""
        top_k: list[str] = []
        if isinstance(output, dict):
            top_k = [str(p) for p in output.get("top_k_predictions", [])[: self._k]]
            if not top_k:
                # Fallback: check single prediction as k=1
                single = output.get("prediction", output.get("completion", ""))
                top_k = [str(single)]
        else:
            top_k = [str(output)]

        ref_text = ""
        if isinstance(reference, dict):
            ref_text = str(reference.get("answer", reference.get("target", "")))
        else:
            ref_text = str(reference)

        normalize = self._accuracy_scorer._normalize
        ref_norm = normalize(ref_text)
        return 1.0 if any(normalize(p) == ref_norm for p in top_k) else 0.0
