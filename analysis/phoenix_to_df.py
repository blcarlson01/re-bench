from pathlib import Path
import json
import pandas as pd


def phoenix_events_to_df(path):
    event_path = Path(path)
    if not event_path.exists():
        return pd.DataFrame()

    rows = []
    with event_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value:
                continue
            try:
                rows.append(json.loads(value))
            except json.JSONDecodeError:
                continue

    return pd.DataFrame(rows)
