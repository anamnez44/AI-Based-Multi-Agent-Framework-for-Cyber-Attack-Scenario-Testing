"""Streamlit dashboard over the run history. Run with: streamlit run ui/app.py"""

import pandas as pd
import streamlit as st

from cyberloop import storage
from cyberloop.config import Settings

st.set_page_config(page_title="Cyberloop dashboard", layout="wide")
st.title("Closed-loop attack testing - run history")

settings = Settings()
conn = storage.connect(settings.history_db)
runs = storage.list_runs(conn, limit=1000)

if not runs:
    st.info("No runs yet. Populate the history with: python scripts/run_experiments.py")
    st.stop()

df = pd.DataFrame(runs)

with st.sidebar:
    st.header("Filters")
    models = st.multiselect("Model", sorted(df["model"].unique()), default=list(df["model"].unique()))
    scenarios = st.multiselect("Scenario", sorted(df["attack_type"].unique()),
                               default=list(df["attack_type"].unique()))

view = df[df["model"].isin(models) & df["attack_type"].isin(scenarios)]
done = view[view["status"] == "completed"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Runs", len(view))
c2.metric("Completed", len(done))
c3.metric("Failed", int((view["status"] != "completed").sum()))
c4.metric("Protected", f"{done['blocked'].mean():.0%}" if len(done) else "-")

st.subheader("Single-pass vs closed-loop (completed runs)")
if len(done):
    comparison = (
        done.groupby(["model", "attack_type", "mode"])
        .agg(
            runs=("id", "count"),
            protected_rate=("blocked", "mean"),
            avg_iterations=("iterations", "mean"),
            avg_final_success=("final_success_rate", "mean"),
            avg_duration_s=("duration_s", "mean"),
        )
        .reset_index()
    )
    st.dataframe(comparison, use_container_width=True, hide_index=True)

    comparison["case"] = comparison["model"] + " / " + comparison["attack_type"]
    protected = comparison.pivot_table(
        index="case", columns="mode", values="protected_rate"
    ).fillna(0)
    st.subheader("Protected rate by mode")
    st.bar_chart(protected)

st.subheader("Recent runs")
st.dataframe(
    view[["id", "created_at", "model", "attack_type", "mode", "status", "blocked", "iterations",
          "final_success_rate", "defenses_applied", "duration_s", "error"]],
    use_container_width=True,
    hide_index=True,
)
