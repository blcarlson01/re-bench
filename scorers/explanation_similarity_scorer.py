from inspect_ai.scorer import Scorer
from bert_score import score as bert_score
from rouge_score import rouge_scorer

class ExplanationSimilarityScorer(Scorer):
    def score(self, output, reference):
        pred = output.get("explanation", "")
        ref = reference.get("true_explanation") or reference.get("explanation", "")

        if not pred or not ref:
            return 0.0

        P, R, F1 = bert_score([pred], [ref], lang="en", rescale_with_baseline=True)
        bert_f1 = max(0.0, min(1.0, float(F1[0])))

        rouge = rouge_scorer.RougeScorer(["rougeL"], use_stemmer=True)
        rouge_l = rouge.score(ref, pred)["rougeL"].fmeasure

        combined = (bert_f1 + rouge_l) / 2.0
        return max(0.0, min(1.0, float(combined)))