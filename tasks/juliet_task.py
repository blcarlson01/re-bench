from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample, csv_dataset
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/juliet/juliet.csv")


def _juliet_record_to_sample(record: dict) -> Sample:
    code = record.get("source", "")
    cwe = (record.get("cwe") or "NONE").strip() or "NONE"
    return Sample(
        id=str(record.get("filename", "")),
        input=(
            "Analyze the following code and identify the CWE:\n\n"
            f"{code}\n\n"
            "Respond with a CWE identifier (e.g., CWE-79)."
        ),
        target=cwe,
        metadata={"filename": str(record.get("filename", ""))},
    )


@task
def juliet_task() -> Task:
    """Juliet CWE identification task.

    Each sample presents a code snippet to the model and asks it to identify
    the CWE (e.g. CWE-79). Scored with match(location='any').
    """
    if _DATASET_PATH.exists():
        dataset = csv_dataset(str(_DATASET_PATH), sample_fields=_juliet_record_to_sample)
    else:
        dataset = MemoryDataset(
            [
                Sample(
                    id="fallback-0",
                    input=(
                        "Analyze the following code and identify the CWE:\n\n"
                        "void bad() { int data = -1; printf(\"%d\", data); }\n\n"
                        "Respond with a CWE identifier (e.g., CWE-79)."
                    ),
                    target="CWE-134",
                )
            ],
            name="juliet",
        )

    return Task(
        dataset=dataset,
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "juliet", "source": str(_DATASET_PATH)},
    )