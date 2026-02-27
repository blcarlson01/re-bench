from loaders.task_loader import load_task_yaml, load_samples
from scorers.malware_scorer import MalwareBehaviorScorer
from scorers.hallucination_scorer import HallucinationScorer
from tracing.phoenix_logger import PhoenixTraceLogger
import csv

phoenix = PhoenixTraceLogger()
scorer = MalwareBehaviorScorer()
hallucination = HallucinationScorer()

task = load_task_yaml("tasks/malware_behavior.yaml")
samples = load_samples("data/malware/samples")
rows = []

for s in samples:
    prompt = task["question"].format(**s)
    output = model(prompt)  # inspect-ai model wrapper
    score = scorer.score(output, s["reference"])
    halluc = hallucination.score(output, s["reference"], context=s)
    print("Score:", score, "Hallucination:", halluc)
    rows.append({
        "sample_id": s["id"],
        "malware_score": score,
        "vuln_f1": vuln_score,
        "hallucination_penalty": halluc
    })

with open("results/latest_run.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)