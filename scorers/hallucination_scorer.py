from inspect_ai.scorers import Scorer

class HallucinationScorer(Scorer):
    def score(self, output, context):
        text = output.get("explanation", "")
        input_tokens = " ".join(context.get("code", []) + context.get("imports", []))
        hallucinated_tokens = [tok for tok in text.split() if tok not in input_tokens]
        return max(0.0, 1.0 - 0.1 * len(hallucinated_tokens))