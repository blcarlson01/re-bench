# RE-Bench

Reverse Engineering & Vulnerability Benchmark for LLMs

RE-Bench is a modular evaluation framework for testing large language models
on malware analysis, vulnerability reasoning, and reverse engineering tasks.

It integrates:

- Inspect-AI for task execution
- Phoenix for trace logging
- Real-world datasets (EMBER, Juliet, Big-Vul, MalwareBazaar)
- Automated scoring
- Full analysis + visualizations

---

# What RE-Bench Evaluates

1. Malware Classification (EMBER)
2. Vulnerability Detection (Big-Vul, Juliet)
3. CWE Identification
4. Explanation Quality (BERTScore / ROUGE)
5. Hallucination Detection
6. Model Regression Over Time

---

# Installation

Recommended Python 3.10+

Install dependencies:

pip install inspect-ai phoenix bert-score rouge-score pandas matplotlib plotly

---

# Dataset Setup

Place datasets into:

data/datasets/

Supported:

- EMBER
- Juliet Test Suite
- Big-Vul CSV
- MalwareBazaar metadata CSV

Use scripts in:

scripts/

to download and preprocess automatically.

---

# Running Evaluations

Run any benchmark:

inspect eval configs/ember.yaml
inspect eval configs/bigvul.yaml
inspect eval configs/juliet.yaml
inspect eval configs/malwarebazaar.yaml

Results are written to:

results/runs/latest_run.csv

---

# Analysis & Visualization

Generate evaluation plots:

python analysis/run_analysis.py

This produces:

- Per-CWE heatmaps
- Behavior confusion matrices
- Model version regression plots
- Hallucination taxonomy charts

You can extend this to Plotly dashboards if desired.

---

# How Scoring Works

MalwareBehaviorScorer:
Binary classification accuracy.

VulnF1Scorer:
Precision / Recall / F1 over CWE labels.

ExplanationSimilarityScorer:
BERTScore semantic similarity between predicted and ground truth explanation.

HallucinationScorer:
Penalizes references to nonexistent APIs, syscalls, registry keys, etc.

---

# Extending RE-Bench

To add a new dataset:

1. Add loader in data/
2. Add Inspect task in tasks/
3. Add YAML config in configs/
4. Ensure scorer compatibility

---

# Design Goals

- Deterministic scoring
- Transparent metrics
- Real-world datasets
- Reproducible evaluation
- LLM-verifiable architecture

---

# Safety

RE-Bench does not execute malware binaries.
MalwareBazaar integration uses metadata only.

---

# License

Research use recommended.
Ensure compliance with dataset licenses.