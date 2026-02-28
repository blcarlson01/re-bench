import pandas as pd
import plotly.express as px


def build_dashboard_figure(csv_path="results/latest_run.csv"):
    df = pd.read_csv(csv_path)
    fig = px.scatter(
        df,
        x="malware_score",
        y="vuln_f1",
        color="model_version",
        title="Malware vs Vulnerability Performance",
    )
    return fig


def main(csv_path="results/latest_run.csv"):
    fig = build_dashboard_figure(csv_path)
    fig.show()


if __name__ == "__main__":
    main()