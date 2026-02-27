from inspect_ai import task
from inspect_ai.scorer import accuracy
from phoenix.trace import log_event

@task
def ember_malware_task(sample):
    prompt = f"""
You are a malware analyst.

Given this sample metadata:
SHA256: {sample['sha256']}

Is this malware or benign? Explain.
"""

    answer = sample.model(prompt)

    pred = "malware" if "malware" in answer.lower() else "benign"

    if "CreateRemoteThread" in answer:
        log_event("hallucination", {"type": "invented_api", "text": answer})

    return {
        "pred_behavior": pred,
        "true_behavior": sample["true_behavior"],
        "explanation": answer
    }