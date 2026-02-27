from inspect_ai.scorers import Scorer

class VulnF1Scorer(Scorer):
    def score(self, output, reference):
        pred = {output.get("pred_cwe")}
        ref = {reference.get("true_cwe")}
        tp = len(pred & ref)
        precision = tp / len(pred) if pred else 0
        recall = tp / len(ref) if ref else 0
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)