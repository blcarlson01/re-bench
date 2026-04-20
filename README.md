# RE-Bench

Reverse Engineering & Vulnerability Benchmark for LLMs

RE-Bench is a modular evaluation framework for testing large language models
on malware analysis, vulnerability reasoning, and reverse engineering tasks.

It integrates:

- Inspect-AI for task execution
- Phoenix for trace logging
- Real-world datasets (EMBER, Juliet, Big-Vul, MalwareBazaar, BIG-15, MELD, Malrec, SOREL-20M)
- Automated scoring
- Full analysis + visualizations

---

# What RE-Bench Evaluates

1. Malware Classification (EMBER)
2. Vulnerability Detection (Big-Vul, Juliet)
3. CWE Identification
4. MITRE ATT&CK Technique Mapping (BIG-15, MELD)
5. Malware Capability Extraction (MELD, Malrec)
6. Assembly Code Understanding (BIG-15)
7. Malware Family Classification (BIG-15)
8. Behavior Explanation Quality (MELD, Malrec)
9. Explanation Quality (BERTScore / ROUGE)
10. Hallucination Detection
11. Model Regression Over Time
12. PE Behavioral Tag Prediction (SOREL-20M)
13. Temporal Drift — accuracy vs. first-seen cohort (SOREL-20M)

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
- BIG-15 (assembly snippets — MITRE mapping, family classification, assembly understanding)
- MELD (API traces + sandbox reports — capability extraction, MITRE mapping, behavior explanation)
- Malrec (execution traces — behavior explanation, capability extraction)
- SOREL-20M (PE metadata — behavioral tag prediction, temporal drift evaluation)

Use scripts in:

scripts/

to download and preprocess automatically. For datasets (BIG-15, MELD, Malrec),
run the corresponding preprocess script:

```bash
python scripts/preprocess_big15.py --sample 60   # or --path <dir>
python scripts/preprocess_meld.py   --sample 60
python scripts/preprocess_malrec.py --sample 60
```

For SOREL-20M, choose one of:

```bash
# Quick synthetic sample — no download required:
python scripts/fetch_sorel.py --sample 60

# Full download from S3 (~3.5 GB, requires AWS CLI, no credentials needed):
# ⚠️  Accept the Sophos/ReversingLabs Terms of Use first:
# https://github.com/sophos/SOREL-20M/blob/master/Terms%20and%20Conditions%20of%20Use.pdf
python scripts/fetch_sorel.py --fetch --sample 1000

# Or process an already-downloaded meta.db:
python scripts/preprocess_sorel.py --path data/datasets/sorel/meta.db --sample 1000
```

---

# Model Configuration

### 1. Point Inspect-AI at the remote host

Set the `OLLAMA_BASE_URL` environment variable to the remote Ollama API
endpoint before running `inspect eval`.

**Linux / macOS**
```bash
export PYTHONPATH=.
inspect eval configs/ember.yaml --model ollama/llama3 --model-base-url http://<remote-host-ip>:11434/v1
```

**Windows (PowerShell)**
```powershell
$env:PYTHONPATH = "."
inspect eval configs/ember.yaml --model ollama/llama3 --model-base-url http://<remote-host-ip>:11434/v1
```

Replace `<remote-host-ip>` with the IP address or hostname of the machine
running Ollama, and `llama3` with your chosen model name (must match the name
shown by `ollama list` on the remote host).

> **Note:** `--model-base-url` takes precedence over the `OLLAMA_BASE_URL`
> environment variable and is the most reliable way to target a specific remote
> host. Always append `/v1` to the Ollama base URL (e.g. `http://192.168.86.230:11434/v1`).

### 2. Evaluate all benchmarks against the remote model

```bash
for cfg in configs/ember.yaml configs/bigvul.yaml configs/juliet.yaml configs/malwarebazaar.yaml \
           configs/big15.yaml configs/meld.yaml configs/malrec.yaml configs/sorel.yaml; do
    inspect eval "$cfg" --model ollama/llama3
done
```

```powershell
# PowerShell equivalent
foreach ($cfg in "configs/ember.yaml","configs/bigvul.yaml","configs/juliet.yaml","configs/malwarebazaar.yaml",
                 "configs/big15.yaml","configs/meld.yaml","configs/malrec.yaml","configs/sorel.yaml") {
    inspect eval $cfg --model ollama/llama3 --model-base-url http://<remote-host-ip>:11434/v1
}
```

---

# Running Evaluations

Run any benchmark:

```bash
# With PYTHONPATH and remote Ollama pre-configured (see above)
inspect eval configs/ember.yaml --model ollama/llama3
inspect eval configs/bigvul.yaml --model ollama/llama3
inspect eval configs/juliet.yaml --model ollama/llama3
inspect eval configs/malwarebazaar.yaml --model ollama/llama3

# datasets (preprocess first — see Dataset Setup above)
inspect eval configs/big15.yaml --model ollama/llama3
inspect eval configs/meld.yaml --model ollama/llama3
inspect eval configs/malrec.yaml --model ollama/llama3

# SOREL-20M (fetch_sorel.py or preprocess_sorel.py first — see Dataset Setup above)
inspect eval configs/sorel.yaml --model ollama/llama3
```

After any eval, generate the full benchmark report:

```bash
python scripts/convert_latest_eval_to_csv.py
python evaluation/scoring.py --predictions results/runs/<name>_predictions.jsonl \
    --tasks data/datasets/<name> --output results/runs/<name>_benchmark_report.json
```

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
Binary classification accuracy (malware vs. benign).

AccuracyScorer (behavior_tag_prediction):
Exact-match accuracy for SOREL-20M behavioral tag labels
(ransomware, trojan, backdoor, downloader, loader, worm, coinminer, virus).
The ``time_period`` metadata field (2018-H1 through 2020-H2) enables
temporal drift plots in analysis/run_analysis.py: accuracy broken down
by half-year first-seen cohort reveals whether model performance degrades
on samples from later in the dataset.

VulnF1Scorer:
Precision / Recall / F1 over CWE labels.

AccuracyScorer:
Exact-match accuracy with label normalization for MITRE technique mapping
and malware family classification. Handles synonyms (e.g. "process injection" → T1055)
and strips sub-technique suffixes (T1055.001 → T1055).

LLMJudgeScorer:
Rubric-based judge (0–3, normalized to [0,1]) for assembly understanding and
behavior explanation tasks. Falls back to keyword-overlap heuristic when
an LLM judge is unavailable.

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