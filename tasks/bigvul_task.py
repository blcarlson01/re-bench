from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample, csv_dataset
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/bigvul/bigvul.csv")


def _bigvul_record_to_sample(record: dict) -> Sample:
    code = record.get("func", "")
    cwe = (record.get("cwe") or "NONE").strip() or "NONE"
    return Sample(
        id=str(record.get("id", "")),
        input=(
            "You are a vulnerability researcher.\n"
            "Analyze the following C function and identify the CWE if vulnerable:\n\n"
            f"{code}\n\n"
            "Respond with a CWE identifier (e.g., CWE-79) or 'NONE' if not vulnerable."
        ),
        target=cwe,
        metadata={"sample_id": str(record.get("id", ""))},
    )


@task
def bigvul_task() -> Task:
    """Big-Vul vulnerability detection task.

    Each sample presents a C function to the model and asks it to identify
    the CWE (e.g. CWE-79) or respond 'NONE'. Scored with match(location='any').
    """
    if _DATASET_PATH.exists():
        dataset = csv_dataset(str(_DATASET_PATH), sample_fields=_bigvul_record_to_sample)
    else:
        dataset = MemoryDataset(
            [
                Sample(
                    id="fallback-0",
                    input=(
                        "You are a vulnerability researcher.\n"
                        "Analyze the following C function and identify the CWE if vulnerable:\n\n"
                        "int foo(char *src) { strcpy(buf, src); return 0; }\n\n"
                        "Respond with a CWE identifier (e.g., CWE-79) or 'NONE' if not vulnerable."
                    ),
                    target="CWE-121",
                )
            ],
            name="bigvul",
        )

    return Task(
        dataset=dataset,
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "bigvul", "source": str(_DATASET_PATH)},
    )