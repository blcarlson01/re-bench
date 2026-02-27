import matplotlib.pyplot as plt

def plot_time_series(df):
    for model in df["model_version"].unique():
        sub = df[df["model_version"] == model]
        plt.plot(sub["run"], sub["malware_score"], marker="o", label=model)
    plt.title("Malware Score by Model Version")
    plt.legend()
    plt.show()

def plot_cwe_heatmap(df_cwe):
    plt.imshow(df_cwe.values, aspect="auto")
    plt.xticks(range(len(df_cwe.columns)), df_cwe.columns)
    plt.yticks(range(len(df_cwe.index)), df_cwe.index)
    plt.title("Per-CWE Heatmap")
    plt.colorbar()
    plt.show()

def plot_behavior_confusion(conf):
    plt.imshow(conf.values, aspect="auto")
    plt.xticks(range(len(conf.columns)), conf.columns, rotation=45)
    plt.yticks(range(len(conf.index)), conf.index)
    plt.title("Behavior Confusion Matrix")
    plt.colorbar()
    plt.show()

def plot_hallucination_taxonomy(df_h):
    import matplotlib.pyplot as plt

    plt.figure()
    plt.bar(df_h["type"], df_h["count"])
    plt.title("Hallucination Taxonomy Counts")
    plt.xlabel("Hallucination Type")
    plt.ylabel("Count")
    plt.show()