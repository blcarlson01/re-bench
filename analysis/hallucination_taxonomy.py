import pandas as pd


def classify_hallucination(text):
    value = str(text).lower()
    if "syscall" in value:
        return "imagined_syscall"
    if "reg\\" in value or "hkey_" in value:
        return "nonexistent_registry"
    if "createremotethread" in value or "imaginary_function" in value:
        return "invented_api"
    return "unknown"


def summarize_hallucinations(df, explanation_column="explanation"):
    if explanation_column not in df.columns:
        return pd.DataFrame(columns=["type", "count"])

    temp = df.copy()
    temp["type"] = temp[explanation_column].map(classify_hallucination)
    out = temp.groupby("type").size().reset_index(name="count")
    return out.sort_values("count", ascending=False)
