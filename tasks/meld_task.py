import json
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/meld/meld.jsonl")

_TASK_PROMPTS = {
    "capability_extraction": (
        "You are a malware analyst.\n"
        "Given the following API call sequence:\n\n"
        "{input}\n\n"
        "Identify the primary malicious capability demonstrated. "
        "Respond with a short capability name (e.g., 'process injection', 'keylogging')."
    ),
    "mitre_mapping": (
        "You are a malware analyst.\n"
        "Given the following API call sequence:\n\n"
        "{input}\n\n"
        "Identify the MITRE ATT&CK technique ID (e.g., T1055). "
        "Respond with just the technique ID."
    ),
    "behavior_explanation": (
        "You are a malware analyst reviewing a sandbox report.\n"
        "Analyze the following sandbox activity:\n\n"
        "{input}\n\n"
        "Describe the malware behavior in one or two sentences, "
        "identifying the primary threat activity."
    ),
}


def _record_to_sample(record: dict, idx: int) -> Sample:
    task_type = record.get("task", "capability_extraction")
    template = _TASK_PROMPTS.get(task_type, _TASK_PROMPTS["capability_extraction"])
    return Sample(
        id=str(record.get("id", idx)),
        input=template.format(input=record.get("input", "")),
        target=str(record.get("answer", "")),
        metadata={
            "dataset": "meld",
            "artifact_type": record.get("artifact_type", "api_trace"),
            "task_type": task_type,
        },
    )


@task
def meld_task() -> Task:
    """MELD API-trace and sandbox analysis task.

    Samples cover three task types from the mama_bench spec:
    capability_extraction, mitre_mapping, and behavior_explanation.
    Each sample presents an API trace or sandbox report snippet;
    scored with match(location='any').
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
                    "You are a malware analyst.\n"
                    "Given the following API call sequence:\n\n"
                    "OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread\n\n"
                    "Identify the MITRE ATT&CK technique ID (e.g., T1055). "
                    "Respond with just the technique ID."
                ),
                target="T1055",
                metadata={"dataset": "meld", "artifact_type": "api_trace", "task_type": "mitre_mapping"},
            )
        )

    return Task(
        dataset=MemoryDataset(samples, name="meld"),
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "meld", "source": str(_DATASET_PATH)},
    )
