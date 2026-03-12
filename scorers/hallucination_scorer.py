import re
from inspect_ai.scorer import Scorer

class HallucinationScorer(Scorer):
    def score(self, output, context):
        text = output.get("explanation", "") if isinstance(output, dict) else str(output)
        if not text:
            return 1.0

        grounded_fields = []
        if isinstance(context, dict):
            for key in ("code", "imports", "sha256", "family", "file_type", "sample_id"):
                value = context.get(key)
                if value is None:
                    continue
                if isinstance(value, list):
                    grounded_fields.extend([str(v) for v in value])
                else:
                    grounded_fields.append(str(value))

        grounded_text = " ".join(grounded_fields).lower()
        output_tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_.-]*", text.lower())

        if not output_tokens:
            return 1.0

        hallucinated = [token for token in output_tokens if token not in grounded_text]
        hallucination_ratio = len(hallucinated) / len(output_tokens)
        return max(0.0, min(1.0, 1.0 - hallucination_ratio))