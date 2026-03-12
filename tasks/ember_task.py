import json
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/ember/ember.json")


@task
def ember_malware_task() -> Task:
    """EMBER malware classification task.

    Each sample presents a SHA256 hash to the model and asks it to classify
    the file as 'malware' or 'benign'. Scored with match(location='any').
    """
    samples: list[Sample] = []

    if _DATASET_PATH.exists():
        with _DATASET_PATH.open("r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sha256 = str(record.get("sha256", f"sample_{idx}"))
                target = "malware" if int(record.get("label", 0)) == 1 else "benign"
                samples.append(
                    Sample(
                        id=str(idx),
                        input=(
                            "You are a malware analyst.\n"
                            f"SHA256: {sha256}\n\n"
                            "Respond with exactly one word: malware or benign."
                        ),
                        target=target,
                        metadata={"sha256": sha256},
                    )
                )

    if not samples:
        samples.append(
            Sample(
                id="fallback-0",
                input=(
                    "You are a malware analyst.\n"
                    "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n"
                    "Respond with exactly one word: malware or benign."
                ),
                target="benign",
                metadata={"sha256": "fallback"},
            )
        )

    return Task(
        dataset=MemoryDataset(samples, name="ember"),
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "ember", "source": str(_DATASET_PATH)},
    )