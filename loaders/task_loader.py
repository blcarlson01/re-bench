import yaml, json, pathlib

def load_task_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)

def load_samples(data_dir):
    samples = []
    for p in pathlib.Path(data_dir).glob("*.json"):
        with open(p) as f:
            samples.append(json.load(f))
    return samples