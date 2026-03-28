import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from ui_utils import PLOTLY_CONFIG, init_state, inject_global_styles, render_logo_header, render_sidebar, safe_round

st.set_page_config(page_title="CyberScan · History", page_icon="📅", layout="wide")
init_state()
inject_global_styles()
render_sidebar("📅 History")
render_logo_header("History & Comparison", "Review saved scans from the backend database and explore how the score set changes over time.", compact=True)

target = st.session_state.get("target")
backend_url = st.session_state.get("backend_url", "http://127.0.0.1:8000").rstrip("/")
if not target:
    st.warning("Set the target in the left Control Center first.")
    st.stop()

try:
    response = requests.get(f"{backend_url}/history/{target}", timeout=30)
    response.raise_for_status()
    history_payload = response.json().get("history", [])
except requests.RequestException as exc:
    st.error(f"Unable to load history: {exc}")
    st.stop()

if not history_payload:
    st.warning("No history is available yet. Run at least one scan from the Summary page.")
    st.stop()

st.session_state.history_backend = history_payload
rows = []
for idx, entry in enumerate(history_payload, start=1):
    rows.append(
        {
            "Run": idx,
            "Timestamp": entry.get("timestamp", "Unknown"),
            "Exposure": safe_round(entry.get("exposure", 0)),
            "Threat": safe_round(entry.get("threat", 0)),
            "Context": safe_round(entry.get("context", 0)),
            "Risk": safe_round(entry.get("risk", 0)),
        }
    )

df = pd.DataFrame(rows)
st.dataframe(df, use_container_width=True, hide_index=True)
st.markdown(
    "<div class='cs-soft-card'><b>How history is saved</b><br>Each scan is written by the backend into the SQLite database with target, timestamp, exposure, threat, context, and risk. This page reads that saved history back through the backend history endpoint.</div>",
    unsafe_allow_html=True,
)

metric = st.selectbox("Metric to explore", ["Exposure", "Threat", "Context", "Risk"], index=3)
trend_fig = px.line(df, x="Run", y=metric, markers=True, hover_data=["Timestamp"], title=f"{metric} movement over time")
trend_fig.update_layout(height=390, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(trend_fig, use_container_width=True, config=PLOTLY_CONFIG)

multi_fig = px.line(df, x="Run", y=["Exposure", "Threat", "Context", "Risk"], markers=True, hover_data=["Timestamp"], title="Full historical comparison")
multi_fig.update_layout(height=430, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(multi_fig, use_container_width=True, config=PLOTLY_CONFIG)

if len(df) >= 2:
    latest = df.iloc[-1]
    previous = df.iloc[-2]
    comp_df = pd.DataFrame(
        {
            "Metric": ["Exposure", "Threat", "Context", "Risk"] * 2,
            "Score": [latest["Exposure"], latest["Threat"], latest["Context"], latest["Risk"], previous["Exposure"], previous["Threat"], previous["Context"], previous["Risk"]],
            "Run Label": [f"Run {int(latest['Run'])}"] * 4 + [f"Run {int(previous['Run'])}"] * 4,
        }
    )
    comp_fig = px.bar(comp_df, x="Metric", y="Score", color="Run Label", barmode="group", text="Score", title="Latest run vs previous run")
    comp_fig.update_traces(textposition="outside")
    comp_fig.update_layout(height=410, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(comp_fig, use_container_width=True, config=PLOTLY_CONFIG)
