import csv
from pathlib import Path

from loaders.task_loader import load_samples, load_task_yaml
from scorers.hallucination_scorer import HallucinationScorer
from scorers.malware_scorer import MalwareBehaviorScorer
from tracing.phoenix_logger import PhoenixTraceLogger


def evaluate(
    model,
    task_path="tasks/malware_behavior.yaml",
    samples_dir="data/malware/samples",
    output_csv="results/latest_run.csv",
):
    phoenix = PhoenixTraceLogger()
    scorer = MalwareBehaviorScorer()
    hallucination = HallucinationScorer()

    task = load_task_yaml(task_path)
    samples = load_samples(samples_dir)
    rows = []

    for sample in samples:
        prompt = task["question"].format(**sample)
        output = model(prompt)

        score = scorer.score(output, sample.get("reference", {}))
        halluc = hallucination.score(output, sample)
        rows.append(
            {
                "sample_id": sample.get("id", "unknown"),
                "malware_score": score,
                "vuln_f1": sample.get("vuln_f1", 0.0),
                "hallucination_penalty": halluc,
            }
        )

    out_path = Path(output_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys() if rows else ["sample_id", "malware_score", "vuln_f1", "hallucination_penalty"],
        )
        writer.writeheader()
        writer.writerows(rows)

    return {
        "rows": len(rows),
        "output_csv": str(out_path),
        "phoenix": phoenix.__class__.__name__,
    }


def main():
    raise RuntimeError("run_eval.main requires a model callable; call evaluate(model=...) from code.")


if __name__ == "__main__":
    main()