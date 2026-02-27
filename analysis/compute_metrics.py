import pandas as pd

def compute_cwe_matrix(df):
    return df.pivot_table(
        index="model_version",
        columns="cwe",
        values="vuln_f1",
        aggfunc="mean"
    )

def compute_behavior_confusion(df):
    return pd.crosstab(df["true_behavior"], df["pred_behavior"])