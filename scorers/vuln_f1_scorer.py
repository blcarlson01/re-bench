from inspect_ai.scorer import Scorer


class VulnF1Scorer(Scorer):
    def score(self, output, reference):
        pred_value = output.get("pred_cwe")
        true_value = reference.get("true_cwe")

        pred = {str(pred_value).strip()} if pred_value else set()
        ref = {str(true_value).strip()} if true_value else set()

        tp = len(pred & ref)
        precision = tp / len(pred) if pred else 0.0
        recall = tp / len(ref) if ref else 0.0

        if precision + recall == 0:
            return 0.0
        return float(2 * (precision * recall) / (precision + recall))

    @staticmethod
    def macro_f1(pred_labels, true_labels):
        labels = sorted(set(pred_labels) | set(true_labels))
        if not labels:
            return 0.0

        per_label = VulnF1Scorer.per_cwe_f1(pred_labels, true_labels)
        return float(sum(per_label.values()) / len(per_label))

    @staticmethod
    def per_cwe_f1(pred_labels, true_labels):
        labels = sorted(set(pred_labels) | set(true_labels))
        result = {}

        for label in labels:
            tp = sum(1 for p, t in zip(pred_labels, true_labels) if p == label and t == label)
            fp = sum(1 for p, t in zip(pred_labels, true_labels) if p == label and t != label)
            fn = sum(1 for p, t in zip(pred_labels, true_labels) if p != label and t == label)

            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 0.0 if (precision + recall) == 0.0 else (2.0 * precision * recall / (precision + recall))
            result[label] = float(f1)

        return result