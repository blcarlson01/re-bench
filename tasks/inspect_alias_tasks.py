"""Registers config-path aliases so that ``inspect eval configs/<name>.yaml``
resolves to the corresponding Python task factory.

Inspect-AI only discovers ``@task``-decorated Python functions, not YAML files.
By registering aliases here with ``@task(name="configs/...")`` and importing
this module at startup (via ``sitecustomize.py``), the CLI can resolve any of
the four config paths directly.
"""

from inspect_ai import task

from tasks.bigvul_task import bigvul_task
from tasks.ember_task import ember_malware_task
from tasks.juliet_task import juliet_task
from tasks.malwarebazaar_task import malwarebazaar_task


@task(name="configs/ember.yaml")
def _ember_config():
    return ember_malware_task()


@task(name="configs/bigvul.yaml")
def _bigvul_config():
    return bigvul_task()


@task(name="configs/juliet.yaml")
def _juliet_config():
    return juliet_task()


@task(name="configs/malwarebazaar.yaml")
def _malwarebazaar_config():
    return malwarebazaar_task()
