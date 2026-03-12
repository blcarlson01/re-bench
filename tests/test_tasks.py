"""Tests for Inspect-AI task factories.

Each task function must be a zero-argument callable decorated with ``@task``
that returns a properly formed ``inspect_ai.Task`` instance containing at
least one sample, a solver, and a scorer.
"""

from inspect_ai import Task


def test_ember_task():
    from tasks.ember_task import ember_malware_task

    result = ember_malware_task()
    assert isinstance(result, Task)
    assert len(result.dataset) >= 1
    assert result.scorer is not None


def test_bigvul_task():
    from tasks.bigvul_task import bigvul_task

    result = bigvul_task()
    assert isinstance(result, Task)
    assert len(result.dataset) >= 1
    assert result.scorer is not None


def test_juliet_task():
    from tasks.juliet_task import juliet_task

    result = juliet_task()
    assert isinstance(result, Task)
    assert len(result.dataset) >= 1
    assert result.scorer is not None


def test_malwarebazaar_task():
    from tasks.malwarebazaar_task import malwarebazaar_task

    result = malwarebazaar_task()
    assert isinstance(result, Task)
    assert len(result.dataset) >= 1
    assert result.scorer is not None

