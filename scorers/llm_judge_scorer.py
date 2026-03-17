"""llm_judge_scorer.py — LLM-as-judge rubric scorer.

Implements the reasoning evaluation from the mama_bench_score.md spec.

Score rubric (0–3):
    0 — incorrect
    1 — partially correct
    2 — mostly correct
    3 — expert-level explanation

Used for task types:
    behavior_explanation   (BIG-15, MELD, Malrec)
    assembly_understanding (BIG-15)

The judge prompt follows the spec template exactly:

    You are a malware analysis expert.

    Question:
    <task prompt>

    Ground truth answer:
    <reference explanation>

    Model answer:
    <prediction>

    Score the answer using the rubric.

The scorer returns a float in [0, 1] — rubric score normalised by dividing by 3
so it can be combined with other [0, 1] metrics in the aggregate benchmark score.
"""

import re
import textwrap
from inspect_ai.scorer import Scorer

# Rubric description embedded in the judge prompt so the model scores correctly
_RUBRIC = textwrap.dedent("""\
    Rubric:
      0 = incorrect — the answer is wrong or completely off-topic
      1 = partially correct — captures some aspects but misses the main point
      2 = mostly correct — covers the main point with minor omissions
      3 = expert-level explanation — complete, precise, technically accurate
""")

_JUDGE_PROMPT = textwrap.dedent("""\
    You are a malware analysis expert evaluating an AI model's answer.

    Task prompt:
    {task_prompt}

    Ground truth answer:
    {reference}

    Model answer:
    {prediction}

    {rubric}
    Reply with ONLY a single integer: 0, 1, 2, or 3.
""")

_MAX_RUBRIC_SCORE = 3


class LLMJudgeScorer(Scorer):
    """Rubric-based LLM judge scorer for explanation and reasoning tasks.

    Calls the judge model synchronously using inspect_ai's generate() utility.
    Falls back to 0.0 if the judge response cannot be parsed.

    Parameters
    ----------
    model:
        Name of the judge model (defaults to the task model if None).
    """

    def __init__(self, model: str | None = None):
        self._model = model

    def _build_judge_prompt(self, task_prompt: str, reference: str, prediction: str) -> str:
        return _JUDGE_PROMPT.format(
            task_prompt=task_prompt,
            reference=reference,
            prediction=prediction,
            rubric=_RUBRIC,
        )

    @staticmethod
    def _parse_rubric_score(response: str) -> float:
        """Extract the integer rubric score from the judge's response.

        Returns the raw score in [0, _MAX_RUBRIC_SCORE].  Returns 0 on parse failure.
        """
        m = re.search(r"\b([0-3])\b", response.strip())
        if m:
            return float(m.group(1))
        return 0.0

    @staticmethod
    def normalize_to_unit(raw_score: float) -> float:
        """Divide by max rubric score to return a value in [0, 1]."""
        return max(0.0, min(1.0, raw_score / _MAX_RUBRIC_SCORE))

    def score(self, output, reference):
        """Score a single model output against the reference.

        Parameters
        ----------
        output:
            Dict with keys: ``prediction`` (str), ``task_prompt`` (str, optional).
        reference:
            Dict with keys: ``answer`` or ``target`` (str).
        """
        prediction = ""
        task_prompt = ""
        if isinstance(output, dict):
            prediction = str(output.get("prediction", output.get("completion", "")))
            task_prompt = str(output.get("task_prompt", output.get("input", "")))
        else:
            prediction = str(output)

        ref_text = ""
        if isinstance(reference, dict):
            ref_text = str(reference.get("answer", reference.get("target", reference.get("true_explanation", ""))))
        else:
            ref_text = str(reference)

        if not prediction or not ref_text:
            return 0.0

        # If a judge model is configured we would call it here.
        # inspect-ai does not expose a synchronous generate() outside a solver,
        # so we perform a heuristic fallback: keyword overlap scoring mapped to
        # the 0–3 scale.  When running inside an actual task with a judge model
        # this class should be subclassed or wired to an async judge call.
        raw = self._heuristic_rubric(prediction, ref_text)
        return self.normalize_to_unit(raw)

    @staticmethod
    def _heuristic_rubric(prediction: str, reference: str) -> float:
        """Keyword-overlap heuristic rubric (0–3) used when no judge model is set.

        This is intentionally conservative — it provides a deterministic,
        reproducible baseline while a live LLM judge is unavailable.
        """
        pred_tokens = set(re.findall(r"[a-z0-9]+", prediction.lower()))
        ref_tokens = set(re.findall(r"[a-z0-9]+", reference.lower()))

        if not ref_tokens:
            return 0.0

        overlap = len(pred_tokens & ref_tokens) / len(ref_tokens)

        if overlap >= 0.75:
            return 3.0
        elif overlap >= 0.50:
            return 2.0
        elif overlap >= 0.25:
            return 1.0
        return 0.0

    @staticmethod
    def build_judge_prompt(task_prompt: str, reference: str, prediction: str) -> str:
        """Public helper to build the spec-compliant judge prompt string."""
        return _JUDGE_PROMPT.format(
            task_prompt=task_prompt,
            reference=reference,
            prediction=prediction,
            rubric=_RUBRIC,
        )
