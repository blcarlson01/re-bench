import matplotlib.pyplot as plt


def plot_cwe_heatmap(df_cwe):
    if df_cwe.empty:
        return
    plt.figure()
    plt.imshow(df_cwe.values, aspect="auto")
    plt.xticks(range(len(df_cwe.columns)), df_cwe.columns)
    plt.yticks(range(len(df_cwe.index)), df_cwe.index)
    plt.title("Per-CWE Heatmap")
    plt.colorbar()
    plt.tight_layout()
    plt.show()
    plt.close()

def plot_behavior_confusion(conf):
    if conf.empty:
        return
    plt.figure()
    plt.imshow(conf.values, aspect="auto")
    plt.xticks(range(len(conf.columns)), conf.columns, rotation=45)
    plt.yticks(range(len(conf.index)), conf.index)
    plt.title("Behavior Confusion Matrix")
    plt.colorbar()
    plt.tight_layout()
    plt.show()
    plt.close()


def plot_hallucination_taxonomy(df_h):
    if df_h.empty:
        return
    plt.figure()
    plt.bar(df_h["type"], df_h["count"])
    plt.title("Hallucination Taxonomy Counts")
    plt.xlabel("Hallucination Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()
    plt.close()