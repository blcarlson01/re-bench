from inspect_ai import task
from phoenix.trace import log_event

@task
def bigvul_task(sample):
    prompt = f"""
You are a vulnerability researcher.

Analyze the following C function and identify the CWE if vulnerable:

{sample['code']}
"""

    answer = sample.model(prompt)

    pred_cwe = "CWE-" + answer.split("CWE-")[-1].split()[0] if "CWE-" in answer else "NONE"

    if "imaginary_function" in answer:
        log_event("hallucination", {"type": "invented_api", "text": answer})

    return {
        "pred_cwe": pred_cwe,
        "true_cwe": sample["cwe"],
        "explanation": answer
    }