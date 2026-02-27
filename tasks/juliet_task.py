from inspect_ai import task
from phoenix.trace import log_event

@task
def juliet_task(sample):
    prompt = f"""
Analyze the code and identify the CWE:

{sample['code']}
"""

    answer = sample.model(prompt)

    pred = "CWE-" + answer.split("CWE-")[-1].split()[0] if "CWE-" in answer else "NONE"

    if "syscall" in answer and "Linux" not in sample["code"]:
        log_event("hallucination", {"type": "imagined_syscall", "text": answer})

    return {
        "pred_cwe": pred,
        "true_cwe": sample["cwe"],
        "explanation": answer
    }