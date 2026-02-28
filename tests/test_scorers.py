import importlib
import sys
import types
from types import SimpleNamespace

from scorers.hallucination_scorer import HallucinationScorer
from scorers.malware_scorer import MalwareBehaviorScorer
from scorers.vuln_f1_scorer import VulnF1Scorer


def test_malware_scorer_score_and_macro():
    scorer = MalwareBehaviorScorer()
    assert scorer.score({"pred_behavior": "malware"}, {"true_behavior": "malware"}) == 1.0
    assert scorer.score({"pred_behavior": "a"}, {"true_behavior": "b"}) == 0.0
    assert scorer.macro_f1(["a", "b"], ["a", "b"]) == 1.0


def test_vuln_scorer_score_and_helpers():
    scorer = VulnF1Scorer()
    assert scorer.score({"pred_cwe": "CWE-79"}, {"true_cwe": "CWE-79"}) == 1.0
    assert scorer.score({"pred_cwe": None}, {"true_cwe": "CWE-79"}) == 0.0
    assert 0.0 <= scorer.macro_f1(["CWE-79", "CWE-89"], ["CWE-79", "CWE-120"]) <= 1.0
    assert isinstance(scorer.per_cwe_f1(["CWE-79"], ["CWE-79"]), dict)


def test_explanation_similarity_scorer(monkeypatch):
    inspect_ai_module = types.ModuleType("inspect_ai")
    inspect_ai_scorer_module = types.ModuleType("inspect_ai.scorer")

    class DummyScorer:
        pass

    inspect_ai_scorer_module.Scorer = DummyScorer
    inspect_ai_module.scorer = inspect_ai_scorer_module

    sys.modules["inspect_ai"] = inspect_ai_module
    sys.modules["inspect_ai.scorer"] = inspect_ai_scorer_module

    bert_score_module = types.ModuleType("bert_score")
    bert_score_module.score = lambda preds, refs, lang, rescale_with_baseline: (None, None, [0.9])
    rouge_module = types.ModuleType("rouge_score")
    rouge_scorer_module = types.ModuleType("rouge_score.rouge_scorer")

    class FakeRouge:
        def score(self, ref, pred):
            return {"rougeL": SimpleNamespace(fmeasure=0.7)}

    rouge_scorer_module.RougeScorer = lambda *a, **k: FakeRouge()
    rouge_module.rouge_scorer = rouge_scorer_module

    sys.modules["bert_score"] = bert_score_module
    sys.modules["rouge_score"] = rouge_module
    sys.modules["rouge_score.rouge_scorer"] = rouge_scorer_module

    if "scorers.explanation_similarity_scorer" in sys.modules:
        del sys.modules["scorers.explanation_similarity_scorer"]
    module = importlib.import_module("scorers.explanation_similarity_scorer")
    scorer = module.ExplanationSimilarityScorer()

    value = scorer.score({"explanation": "a"}, {"explanation": "b"})
    assert 0.0 <= value <= 1.0
    assert scorer.score({"explanation": ""}, {"explanation": "x"}) == 0.0


def test_hallucination_scorer():
    scorer = HallucinationScorer()
    assert scorer.score({"explanation": ""}, {}) == 1.0
    s = scorer.score({"explanation": "token1 token2"}, {"code": "token1"})
    assert 0.0 <= s <= 1.0
