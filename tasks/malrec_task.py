import json
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/malrec/malrec.jsonl")

_TASK_PROMPTS = {
    "behavior_explanation": (
        "You are a malware analyst reviewing an execution trace.\n"
        "Analyze the following recorded system calls and events:\n\n"
        "{input}\n\n"
        "Describe the malware behavior in one or two sentences, "
        "identifying the primary threat activity."
    ),
    "capability_extraction": (
        "You are a malware analyst.\n"
        "Given the following execution trace:\n\n"
        "{input}\n\n"
        "Identify the primary malicious capability demonstrated. "
        "Respond with a short capability name (e.g., 'process injection', 'ransomware')."
    ),
}


def _record_to_sample(record: dict, idx: int) -> Sample:
    task_type = record.get("task", "behavior_explanation")
    template = _TASK_PROMPTS.get(task_type, _TASK_PROMPTS["behavior_explanation"])
    return Sample(
        id=str(record.get("id", idx)),
        input=template.format(input=record.get("input", "")),
        target=str(record.get("answer", "")),
        metadata={
            "dataset": "malrec",
            "artifact_type": record.get("artifact_type", "execution_trace"),
            "task_type": task_type,
        },
    )


@task
def malrec_task() -> Task:
    """Malrec execution-trace analysis task.

    Samples cover two task types from the mama_bench spec:
    behavior_explanation and capability_extraction.
    Each sample presents a system-call execution trace;
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
                    "You are a malware analyst reviewing an execution trace.\n"
                    "Analyze the following recorded system calls and events:\n\n"
                    "NtOpenProcess -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx\n\n"
                    "Describe the malware behavior in one or two sentences, "
                    "identifying the primary threat activity."
                ),
                target="process injection",
                metadata={"dataset": "malrec", "artifact_type": "execution_trace", "task_type": "behavior_explanation"},
            )
        )

    return Task(
        dataset=MemoryDataset(samples, name="malrec"),
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "malrec", "source": str(_DATASET_PATH)},
    )
