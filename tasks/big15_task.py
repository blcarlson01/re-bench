import json
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/big15/big15.jsonl")

_TASK_PROMPTS = {
    "mitre_mapping": (
        "You are a malware reverse engineer.\n"
        "Given the following assembly snippet:\n\n"
        "{input}\n\n"
        "Identify the MITRE ATT&CK technique ID (e.g., T1055). "
        "Respond with just the technique ID."
    ),
    "family_classification": (
        "You are a malware analyst.\n"
        "Given the following assembly snippet:\n\n"
        "{input}\n\n"
        "Identify the malware family. Respond with just the family name."
    ),
    "assembly_understanding": (
        "You are a malware reverse engineer.\n"
        "Analyze the following assembly snippet and describe what it does:\n\n"
        "{input}\n\n"
        "Provide a concise technical explanation (one or two sentences)."
    ),
}


def _record_to_sample(record: dict, idx: int) -> Sample:
    task_type = record.get("task", "mitre_mapping")
    template = _TASK_PROMPTS.get(task_type, _TASK_PROMPTS["mitre_mapping"])
    return Sample(
        id=str(record.get("id", idx)),
        input=template.format(input=record.get("input", "")),
        target=str(record.get("answer", "")),
        metadata={
            "dataset": "big15",
            "artifact_type": record.get("artifact_type", "assembly"),
            "task_type": task_type,
        },
    )


@task
def big15_task() -> Task:
    """BIG-15 malware assembly analysis task.

    Samples cover three task types from the mama_bench spec:
    mitre_mapping, family_classification, and assembly_understanding.
    Each sample presents an assembly snippet; scored with match(location='any').
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
                samples.append(_record_to_sample(record, idx))

    if not samples:
        samples.append(
            Sample(
                id="fallback-0",
                input=(
                    "You are a malware reverse engineer.\n"
                    "Given the following assembly snippet:\n\n"
                    "call OpenProcess\ncall VirtualAllocEx\ncall WriteProcessMemory\ncall CreateRemoteThread\n\n"
                    "Identify the MITRE ATT&CK technique ID (e.g., T1055). "
                    "Respond with just the technique ID."
                ),
                target="T1055",
                metadata={"dataset": "big15", "artifact_type": "assembly", "task_type": "mitre_mapping"},
            )
        )

    return Task(
        dataset=MemoryDataset(samples, name="big15"),
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "big15", "source": str(_DATASET_PATH)},
    )
