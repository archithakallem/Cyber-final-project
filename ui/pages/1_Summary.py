from datetime import datetime

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from ui_utils import (
    PLOTLY_CONFIG,
    get_risk_label,
    init_state,
    inject_global_styles,
    render_logo_header,
    render_sidebar,
    require_scan_inputs,
    safe_round,
    summarise_findings,
)

st.set_page_config(page_title="CyberScan · Summary", page_icon="📊", layout="wide")
init_state()
inject_global_styles()
render_sidebar("📊 Summary")
render_logo_header(
    "Summary Dashboard",
    "Run the scan, review the core metrics, and compare targets when multiple inputs are provided.",
    compact=True,
)
require_scan_inputs()

backend_url = st.session_state.backend_url.rstrip("/")
target = st.session_state.target

st.markdown(
    f"<div class='cs-soft-card'><b>Target input:</b> {target}<br><b>Email alert destination:</b> {st.session_state.email or 'Not set'}<br><b>Backend:</b> {backend_url}</div>",
    unsafe_allow_html=True,
)

if st.button("🚀 Run security scan", use_container_width=True, type="primary"):
    try:
        with st.spinner("Running CyberScan pipeline..."):
            res = requests.get(
                f"{backend_url}/scan/{target}",
                params={"api_key": st.session_state.api_key, "email": st.session_state.email},
                timeout=120,
            )
            res.raise_for_status()
            payload = res.json()
            payload["retrieved_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.scan_data = payload
        st.success("Scan completed successfully.")
    except requests.RequestException as exc:
        st.error(f"Unable to complete scan: {exc}")
        st.stop()

data = st.session_state.get("scan_data")
if not data:
    st.warning("No scan result yet. Run a scan from this page.")
    st.stop()

# ---------------- MULTI TARGET MODE ----------------
if data.get("is_multi_target"):
    comparison = data.get("comparison", [])
    st.markdown("### Multi-target comparison")

    comp_df = pd.DataFrame(comparison)
    st.dataframe(comp_df, use_container_width=True, hide_index=True)

    risk_fig = px.bar(
        comp_df,
        x="target",
        y="risk",
        color="target_type",
        text="risk",
        title="Risk comparison across targets",
    )
    risk_fig.update_traces(textposition="outside")
    risk_fig.update_layout(height=430, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(risk_fig, use_container_width=True, config=PLOTLY_CONFIG)

    metric_fig = px.line(
        comp_df,
        x="target",
        y=["exposure", "threat", "context", "risk"],
        markers=True,
        title="Score comparison by target",
    )
    metric_fig.update_layout(height=430, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(metric_fig, use_container_width=True, config=PLOTLY_CONFIG)

    mal_fig = px.bar(
        comp_df,
        x="target",
        y=["malicious", "open_ports"],
        barmode="group",
        title="Malicious detections and open ports",
    )
    mal_fig.update_layout(height=400, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(mal_fig, use_container_width=True, config=PLOTLY_CONFIG)

    st.markdown("### Quick interpretation")
    highest = comp_df.sort_values("risk", ascending=False).iloc[0]
    st.markdown(
        f"""
        <div class='cs-soft-card'>
        The highest-risk target in this run is <b>{highest['target']}</b> with a risk score of <b>{safe_round(highest['risk'])}</b>.
        This comparison view helps you identify which target has higher exposure, stronger threat signals, or weaker context.
        Email alerts are evaluated separately for each target using the same malicious-or-high-risk rule.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.stop()

# ---------------- SINGLE TARGET MODE ----------------
scores = data.get("scores", {})
structured = data.get("data", {})
ports = structured.get("open_ports", []) or []
risk_value = float(scores.get("risk", 0) or 0)
risk_label, risk_icon = get_risk_label(risk_value)
target_type = data.get("target_type", "Detected automatically")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Exposure", safe_round(scores.get("exposure", 0)))
m2.metric("Threat", safe_round(scores.get("threat", 0)))
m3.metric("Context", safe_round(scores.get("context", 0)))
m4.metric("Risk", safe_round(risk_value))
st.info(f"{risk_icon} Current status: {risk_label}")

score_df = pd.DataFrame(
    {
        "Metric": ["Exposure", "Threat", "Context", "Risk"],
        "Score": [
            safe_round(scores.get("exposure", 0)),
            safe_round(scores.get("threat", 0)),
            safe_round(scores.get("context", 0)),
            safe_round(risk_value),
        ],
    }
)
score_fig = px.bar(score_df, x="Metric", y="Score", text="Score", title="CyberScan score snapshot")
score_fig.update_traces(textposition="outside")
score_fig.update_layout(height=430, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(score_fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("Use the chart toolbar in the top-right to zoom, pan, select, and download the figure.")

st.markdown("### Scan summary")
summary_df = pd.DataFrame(
    {
        "Signal": [
            "Detected target type",
            "Open ports discovered",
            "Malicious detections",
            "Total VT observations",
            "SSL context flag",
            "Security header score",
        ],
        "Value": [
            target_type,
            len(ports),
            structured.get("vt_malicious", 0),
            structured.get("vt_total", 0),
            structured.get("ssl", "Unknown"),
            structured.get("security_headers", "Unknown"),
        ],
    }
)
st.dataframe(summary_df, use_container_width=True, hide_index=True)

st.markdown("### Summary report")
for line in summarise_findings(structured, scores):
    st.markdown(f"<div class='cs-soft-card'>{line}</div>", unsafe_allow_html=True)

st.markdown("### What the system did")
st.markdown(
    """
    <div class='cs-soft-card'>
    CyberScan identified the input type, applied the correct scan path, ran the scanning pipeline, normalized the results,
    calculated exposure, threat, context, and risk scores, and prepared the output for analysis, visualization, history, and alerting.
    </div>
    """,
    unsafe_allow_html=True,
)