# sitecustomize.py – executed automatically by Python on every interpreter
# startup when PYTHONPATH includes the project root.
#
# Importing inspect_alias_tasks here ensures that Inspect-AI's task registry
# contains the "configs/<name>.yaml" aliases before the CLI scans for tasks,
# so that ``inspect eval configs/ember.yaml`` (and the other configs) resolve
# correctly without needing a native Inspect YAML format.
try:
    import tasks.inspect_alias_tasks  # noqa: F401
except ImportError:
    pass
