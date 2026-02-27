import pandas as pd
import matplotlib.pyplot as plt

def analyze_results(csv_path):
    df = pd.read_csv(csv_path)

    # Malware score distribution
    plt.figure()
    plt.hist(df["malware_score"], bins=10)
    plt.title("Distribution of Malware Behavior Scores")
    plt.xlabel("Score")
    plt.ylabel("Frequency")
    plt.show()

    # Vuln F1 distribution
    plt.figure()
    plt.hist(df["vuln_f1"], bins=10)
    plt.title("Distribution of Vulnerability F1 Scores")
    plt.xlabel("F1 Score")
    plt.ylabel("Frequency")
    plt.show()

    # Hallucination penalties
    plt.figure()
    plt.hist(df["hallucination_penalty"], bins=10)
    plt.title("Distribution of Hallucination Penalties")
    plt.xlabel("Penalty Score")
    plt.ylabel("Frequency")
    plt.show()

    # Cross-metric correlation
    plt.figure()
    plt.scatter(df["malware_score"], df["vuln_f1"])
    plt.title("Malware Score vs Vulnerability F1")
    plt.xlabel("Malware Score")
    plt.ylabel("Vulnerability F1")
    plt.show()

    return df

from load_results import load_latest_run
from compute_metrics import compute_cwe_matrix, compute_behavior_confusion
from plots import plot_time_series, plot_cwe_heatmap, plot_behavior_confusion

df = load_latest_run()
plot_time_series(df)
plot_cwe_heatmap(compute_cwe_matrix(df))
plot_behavior_confusion(compute_behavior_confusion(df))