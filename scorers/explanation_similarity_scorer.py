from inspect_ai.scorers import Scorer
from bert_score import score as bert_score

class ExplanationSimilarityScorer(Scorer):
    def score(self, output, reference):
        pred = output.get("explanation", "")
        ref = reference.get("explanation", "")
        P, R, F1 = bert_score([pred], [ref], lang="en", rescale_with_baseline=True)
        return float(F1[0])