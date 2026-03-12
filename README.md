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

# Model Configuration

## Using a Remote Ollama Instance

RE-Bench can evaluate against any model served by an [Ollama](https://ollama.com)
instance running on a separate machine.  Inspect-AI uses the `ollama` provider
which speaks the standard OpenAI-compatible REST API that Ollama exposes.

### 1. Start Ollama on the remote host

On the remote machine, tell Ollama to listen on all interfaces (not just
`127.0.0.1`) and pull the model you want to evaluate:

```bash
# On the remote machine
OLLAMA_HOST=0.0.0.0 ollama serve
ollama pull llama3          # or any other model
```

> **Tip:** use `ollama list` to see every model available on that host.

### 2. Point Inspect-AI at the remote host

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

### 3. Evaluate all benchmarks against the remote model

```bash
for cfg in configs/ember.yaml configs/bigvul.yaml configs/juliet.yaml configs/malwarebazaar.yaml; do
    inspect eval "$cfg" --model ollama/llama3
done
```

```powershell
# PowerShell equivalent
foreach ($cfg in "configs/ember.yaml","configs/bigvul.yaml","configs/juliet.yaml","configs/malwarebazaar.yaml") {
    inspect eval $cfg --model ollama/llama3 --model-base-url http://<remote-host-ip>:11434/v1
}
```

### 4. Specifying the model in task code (optional)

All task factories (`tasks/*.py`) have no hardcoded model — the model is
determined entirely by the `--model` CLI flag at eval time.  This is the
recommended approach.

If you want a task to always use a specific model without passing `--model`
every time, add a `model=` argument to the `Task(...)` constructor:

```python
# tasks/ember_task.py (example)
return Task(
    dataset=MemoryDataset(samples, name="ember"),
    solver=generate(),
    scorer=match(location="any"),
    model="ollama/llama3",   # ← locks this task to a specific model
    metadata={"dataset": "ember"},
)
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