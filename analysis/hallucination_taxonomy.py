def classify_hallucination(text):
    if "syscall" in text:
        return "imagined_syscall"
    if "reg\\" in text:
        return "nonexistent_registry"
    if "CreateRemoteThread" in text:
        return "invented_api"
    return "unknown"