"""sorel_task.py — SOREL-20M behavioral tag prediction task.

Two evaluation goals are served by a single task:

1. **Behavior tag prediction** — given PE metadata (imports, section names,
   notable strings), predict the dominant behavioral category of the sample.
   Valid labels: ransomware, trojan, backdoor, downloader, loader, worm,
   coinminer, virus.

2. **Temporal drift** — the ``time_period`` field in each sample's metadata
   (e.g., "2019-H2") allows analysis/run_analysis.py to break accuracy down
   by half-year cohort, revealing whether model performance degrades on
   samples observed later in the dataset (2018-H1 through 2020-H2).
"""

import json
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import match
from inspect_ai.solver import generate

_DATASET_PATH = Path("data/datasets/sorel/sorel.jsonl")

_BEHAVIORAL_TAGS = [
    "ransomware",
    "trojan",
    "backdoor",
    "downloader",
    "loader",
    "worm",
    "coinminer",
    "virus",
]

_PROMPT_TEMPLATE = (
    "You are a malware analyst examining a PE (Portable Executable) file.\n\n"
    "{input}\n\n"
    "Based on the PE metadata above, identify the primary behavioral category "
    "of this malware sample.  Choose exactly one of the following labels and "
    "respond with that label only:\n"
    "ransomware, trojan, backdoor, downloader, loader, worm, coinminer, virus"
)


def _record_to_sample(record: dict, idx: int) -> Sample:
    sha256 = str(record.get("id", f"sample_{idx}"))
    target = str(record.get("answer", ""))
    return Sample(
        id=sha256,
        input=_PROMPT_TEMPLATE.format(input=record.get("input", "")),
        target=target,
        metadata={
            "dataset": "sorel",
            "artifact_type": "pe_metadata",
            "task_type": "behavior_tag_prediction",
            "first_seen": record.get("first_seen", 0),
            "time_period": record.get("time_period", "unknown"),
        },
    )


@task
def sorel_task() -> Task:
    """SOREL-20M PE behavioral tag prediction task.

    Each sample presents PE imports, section names, and notable strings to the
    model and asks it to identify the dominant behavioral category.  The
    ``time_period`` metadata field enables temporal drift analysis: accuracy
    can be broken down by half-year cohort (2018-H1 through 2020-H2) in
    analysis/run_analysis.py to detect performance degradation on newer samples.

    Scored with match(location='any').
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
                input=_PROMPT_TEMPLATE.format(
                    input=(
                        "PE Imports:\n"
                        "  KERNEL32.dll: CreateFileW, WriteFile, FindFirstFileW, DeleteFileW\n"
                        "  ADVAPI32.dll: CryptAcquireContextA, CryptEncrypt, CryptGenKey\n"
                        "Section Names: .text, .rdata, .data, .rsrc\n"
                        "Strings: YOUR FILES HAVE BEEN ENCRYPTED, .onion, bitcoin"
                    )
                ),
                target="ransomware",
                metadata={
                    "dataset": "sorel",
                    "artifact_type": "pe_metadata",
                    "task_type": "behavior_tag_prediction",
                    "first_seen": 0,
                    "time_period": "unknown",
                },
            )
        )

    return Task(
        dataset=MemoryDataset(samples, name="sorel"),
        solver=generate(),
        scorer=match(location="any"),
        metadata={"dataset": "sorel", "source": str(_DATASET_PATH)},
    )
