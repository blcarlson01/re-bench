import importlib
import sys
import types


def _load_task_module(module_name, monkeypatch):
    inspect_module = types.ModuleType("inspect_ai")
    inspect_module.task = lambda fn: fn
    scorer_module = types.ModuleType("inspect_ai.scorer")
    scorer_module.accuracy = object()

    phoenix_module = types.ModuleType("phoenix")
    phoenix_trace = types.ModuleType("phoenix.trace")
    phoenix_trace.log_event = lambda *a, **k: None

    monkeypatch.setitem(sys.modules, "inspect_ai", inspect_module)
    monkeypatch.setitem(sys.modules, "inspect_ai.scorer", scorer_module)
    monkeypatch.setitem(sys.modules, "phoenix", phoenix_module)
    monkeypatch.setitem(sys.modules, "phoenix.trace", phoenix_trace)

    if module_name in sys.modules:
        del sys.modules[module_name]
    return importlib.import_module(module_name)


class FakeSample(dict):
    def model(self, prompt):
        if "CWE" in prompt:
            return "CWE-79 from analysis"
        if "malware" in prompt.lower():
            return "This is malware and uses CreateRemoteThread"
        return "encrypt files"


def test_ember_task(monkeypatch):
    mod = _load_task_module("tasks.ember_task", monkeypatch)
    out = mod.ember_malware_task(FakeSample({"sha256": "abc", "true_behavior": "malware"}))
    assert set(out.keys()) == {"pred_behavior", "true_behavior", "explanation"}


def test_bigvul_task(monkeypatch):
    mod = _load_task_module("tasks.bigvul_task", monkeypatch)
    out = mod.bigvul_task(FakeSample({"code": "int x", "cwe": "CWE-79"}))
    assert out["pred_cwe"].startswith("CWE-") or out["pred_cwe"] == "NONE"


def test_juliet_task(monkeypatch):
    mod = _load_task_module("tasks.juliet_task", monkeypatch)
    out = mod.juliet_task(FakeSample({"code": "int x", "cwe": "CWE-79"}))
    assert "true_cwe" in out


def test_malwarebazaar_task(monkeypatch):
    mod = _load_task_module("tasks.malwarebazaar_task", monkeypatch)
    out = mod.malwarebazaar_task(FakeSample({"family": "fam", "file_type": "exe"}))
    assert set(out.keys()) == {"pred_behavior", "true_behavior", "explanation"}
