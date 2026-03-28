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
    "Run the scan, review the core metrics, and read a concise report of what the system found and did.",
    compact=True,
)
require_scan_inputs()

backend_url = st.session_state.backend_url.rstrip("/")
target = st.session_state.target

st.markdown(
    f"<div class='cs-soft-card'><b>Target:</b> {target}<br><b>Email alert destination:</b> {st.session_state.email or 'Not set'}<br><b>Backend:</b> {backend_url}</div>",
    unsafe_allow_html=True,
)

if st.button("🚀 Run security scan", use_container_width=True, type="primary"):
    try:
        with st.spinner("Running CyberScan pipeline..."):
            res = requests.get(
                f"{backend_url}/scan/{target}",
                params={"api_key": st.session_state.api_key, "email": st.session_state.email},
                timeout=90,
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

scores = data.get("scores", {})
structured = data.get("data", {})
ports = structured.get("open_ports", []) or []
risk_value = float(scores.get("risk", 0) or 0)
risk_label, risk_icon = get_risk_label(risk_value)

# target type if backend returns it
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

st.markdown("### Resources used for this scan")
resources_df = pd.DataFrame(
    {
        "Resource": ["Nmap", "VirusTotal", "Target type detection"],
        "Purpose": [
            "Identifies visible open ports and exposed services for network-facing targets.",
            "Checks external threat intelligence for domains, IPs, URLs, and file hashes.",
            "Classifies the input as domain, IP, URL, or hash so the correct scan path is applied.",
        ],
    }
)
st.dataframe(resources_df, use_container_width=True, hide_index=True)

st.markdown("### Supported target types")
targets_df = pd.DataFrame(
    {
        "Target type": ["Domain", "IP address", "URL", "File hash"],
        "How CyberScan handles it": [
            "Uses VirusTotal domain intelligence and Nmap network scan.",
            "Uses VirusTotal IP intelligence and Nmap network scan.",
            "Uses VirusTotal URL submission/analysis and extracts the host for Nmap where applicable.",
            "Uses VirusTotal file intelligence only; Nmap is skipped because hashes are not network targets.",
        ],
    }
)
st.dataframe(targets_df, use_container_width=True, hide_index=True)

st.markdown("### Separate analysis charts")

vt_df = pd.DataFrame(
    {
        "Category": ["Malicious", "Other observations"],
        "Count": [
            structured.get("vt_malicious", 0),
            max(structured.get("vt_total", 0) - structured.get("vt_malicious", 0), 0),
        ],
    }
)
vt_fig = px.pie(vt_df, names="Category", values="Count", title="Threat intelligence split", hole=0.45)
vt_fig.update_layout(height=380, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(vt_fig, use_container_width=True, config=PLOTLY_CONFIG)

port_df = pd.DataFrame(ports) if ports else pd.DataFrame(columns=["port", "state"])
if not port_df.empty and "port" in port_df.columns:
    port_fig = px.histogram(port_df, x="port", title="Open port distribution")
    port_fig.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(port_fig, use_container_width=True, config=PLOTLY_CONFIG)

st.markdown("### Summary report")
for line in summarise_findings(structured, scores):
    st.markdown(f"<div class='cs-soft-card'>{line}</div>", unsafe_allow_html=True)

st.markdown("### What the system did")
st.markdown(
    """
    <div class='cs-soft-card'>
    CyberScan first identified the input type so the right analysis path could be used. It then ran Nmap for network-facing targets,
    queried VirusTotal using the matching endpoint for domains, IPs, URLs, or file hashes, normalized the results into reusable fields,
    calculated the score set, and prepared the output for deeper analysis, charting, recommendations, history, and automated alerting.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("### Email alert status")
alert_triggered = data.get("alert_triggered", False)
email_status = data.get("email_status", "Unknown")
st.markdown(
    f"<div class='cs-soft-card'><b>Triggered:</b> {alert_triggered}<br><b>Status:</b> {email_status}<br><b>Rule:</b> Alert is sent only when malicious detections are present or the risk score is greater than 70, and an email address is provided.</div>",
    unsafe_allow_html=True,
)