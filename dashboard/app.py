import pandas as pd
import plotly.express as px

df = pd.read_csv("results/latest_run.csv")

fig = px.scatter(
    df, x="malware_score", y="vuln_f1",
    color="model_version",
    title="Malware vs Vulnerability Performance"
)
fig.show()