import pandas as pd


def _macro_f1_for_columns(df, true_col, pred_col):
    if true_col not in df.columns or pred_col not in df.columns:
        return None

    pairs = df[[true_col, pred_col]].dropna()
    if pairs.empty:
        return None

    y_true = pairs[true_col].astype(str).tolist()
    y_pred = pairs[pred_col].astype(str).tolist()
    labels = sorted(set(y_true) | set(y_pred))

    if not labels:
        return None

    f1_values = []
    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 0.0 if (precision + recall) == 0 else (2.0 * precision * recall / (precision + recall))
        f1_values.append(f1)

    return float(sum(f1_values) / len(f1_values))


def compute_cwe_matrix(df):
    required = {"model_version", "cwe", "vuln_f1"}
    if not required.issubset(df.columns):
        return pd.DataFrame()
    return df.pivot_table(
        index="model_version",
        columns="cwe",
        values="vuln_f1",
        aggfunc="mean"
    )

def compute_behavior_confusion(df):
    required = {"true_behavior", "pred_behavior"}
    if not required.issubset(df.columns):
        return pd.DataFrame()
    return pd.crosstab(df["true_behavior"], df["pred_behavior"])


def compute_rubric_scores(df, weights=None):
    if weights is None:
        weights = {
            "malware_f1": 0.30,
            "cwe_f1": 0.35,
            "explanation_similarity": 0.20,
            "hallucination_robustness": 0.15,
        }

    malware_f1 = _macro_f1_for_columns(df, "true_behavior", "pred_behavior")
    cwe_f1 = _macro_f1_for_columns(df, "true_cwe", "pred_cwe")

    explanation_similarity = None
    for column in ("explanation_similarity", "explanation_score"):
        if column in df.columns:
            explanation_similarity = float(df[column].dropna().mean()) if not df[column].dropna().empty else None
            break

    hallucination_robustness = None
    for column in ("hallucination_score", "hallucination_penalty"):
        if column in df.columns:
            hallucination_robustness = float(df[column].dropna().mean()) if not df[column].dropna().empty else None
            break

    components = {
        "malware_f1": malware_f1,
        "cwe_f1": cwe_f1,
        "explanation_similarity": explanation_similarity,
        "hallucination_robustness": hallucination_robustness,
    }

    composite = 0.0
    composite_weight = 0.0
    for key, value in components.items():
        if value is None:
            continue
        weight = float(weights.get(key, 0.0))
        composite += weight * float(value)
        composite_weight += weight

    if composite_weight == 0.0:
        composite_score = None
    else:
        composite_score = float(composite / composite_weight)

    return {
        **components,
        "composite_score": composite_score,
    }