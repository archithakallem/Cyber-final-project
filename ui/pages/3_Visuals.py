import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ui_utils import (
    PLOTLY_CONFIG,
    get_risk_label,
    init_state,
    inject_global_styles,
    render_logo_header,
    render_sidebar,
    safe_round,
)

st.set_page_config(page_title="CyberScan · Visuals", page_icon="📈", layout="wide")
init_state()
inject_global_styles()
render_sidebar("📈 Visuals")
render_logo_header(
    "Interactive Visuals",
    "A cleaner chart lab with comparisons, distributions, and analysis-focused visuals.",
    compact=True,
)

data = st.session_state.get("scan_data")
if not data:
    st.warning("Run a scan from the Summary page first.")
    st.stop()

scores = data.get("scores", {})
structured = data.get("data", {})
ports = structured.get("open_ports", []) or []

current_scores = {
    "Exposure": safe_round(scores.get("exposure", 0)),
    "Threat": safe_round(scores.get("threat", 0)),
    "Context": safe_round(scores.get("context", 0)),
    "Risk": safe_round(scores.get("risk", 0)),
}
risk_label, risk_icon = get_risk_label(current_scores["Risk"])
st.info(f"{risk_icon} Current interpretation: {risk_label}")

comparison_mode = st.selectbox(
    "Comparison source",
    ["Recommended baseline", "Reduced-exposure target", "Previous scan"]
)
if comparison_mode == "Previous scan" and isinstance(st.session_state.get("history_backend"), list) and len(st.session_state["history_backend"]) >= 2:
    prev = st.session_state["history_backend"][-2]
    compare_scores = {
        "Exposure": safe_round(prev.get("exposure", 0)),
        "Threat": safe_round(prev.get("threat", 0)),
        "Context": safe_round(prev.get("context", 0)),
        "Risk": safe_round(prev.get("risk", 0)),
    }
    compare_label = "Previous scan"
elif comparison_mode == "Reduced-exposure target":
    compare_scores = {"Exposure": 10, "Threat": 5, "Context": 72, "Risk": 29}
    compare_label = "Reduced-exposure target"
else:
    compare_scores = {"Exposure": 20, "Threat": 10, "Context": 85, "Risk": 25}
    compare_label = "Recommended baseline"

st.markdown(
    f"<div class='cs-soft-card'><b>What the comparison means</b><br>The selected reference is <b>{compare_label}</b>. Comparison charts use that same reference, while the analysis charts below focus only on the current scan output.</div>",
    unsafe_allow_html=True,
)

comparison_df = pd.DataFrame(
    {
        "Metric": list(current_scores.keys()) * 2,
        "Score": list(current_scores.values()) + list(compare_scores.values()),
        "Series": ["Current scan"] * 4 + [compare_label] * 4,
    }
)

fig = px.bar(comparison_df, x="Metric", y="Score", color="Series", barmode="group", text="Score", title="Comparison chart")
fig.update_traces(textposition="outside")
fig.update_layout(height=430, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("This grouped chart shows where the current scan stands relative to the selected reference.")

radar = go.Figure()
radar.add_trace(
    go.Scatterpolar(
        r=list(current_scores.values()) + [current_scores["Exposure"]],
        theta=["Exposure", "Threat", "Context", "Risk", "Exposure"],
        fill="toself",
        name="Current scan",
    )
)
radar.add_trace(
    go.Scatterpolar(
        r=list(compare_scores.values()) + [compare_scores["Exposure"]],
        theta=["Exposure", "Threat", "Context", "Risk", "Exposure"],
        fill="toself",
        name=compare_label,
        opacity=0.45,
    )
)
radar.update_layout(
    title="Radar comparison",
    polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
    height=430,
    margin=dict(l=20, r=20, t=55, b=20),
)
st.plotly_chart(radar, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("The radar chart helps show shape differences between the current scan and the selected comparison reference.")

delta_df = pd.DataFrame(
    {
        "Metric": list(current_scores.keys()),
        "Delta": [current_scores[k] - compare_scores[k] for k in current_scores.keys()],
    }
)
delta_fig = px.bar(delta_df, x="Metric", y="Delta", text="Delta", title="Delta versus comparison")
delta_fig.update_traces(texttemplate="%{text:.1f}", textposition="outside")
delta_fig.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(delta_fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("Positive values mean the current scan is higher than the selected reference. Negative values mean it is lower.")

st.markdown("### Current-scan analysis charts")

pie_fig = px.pie(
    values=[current_scores["Exposure"], current_scores["Threat"], current_scores["Context"]],
    names=["Exposure", "Threat", "Context"],
    title="Current score contribution distribution",
    hole=0.45,
)
pie_fig.update_layout(height=390, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(pie_fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("This donut chart shows which main security dimension contributes more heavily to the current scan picture.")

sunburst_df = pd.DataFrame(
    {
        "labels": ["Risk", "Exposure", "Threat", "Context"],
        "parents": ["", "Risk", "Risk", "Risk"],
        "values": [
            max(current_scores["Exposure"] + current_scores["Threat"] + current_scores["Context"], 1),
            current_scores["Exposure"],
            current_scores["Threat"],
            current_scores["Context"],
        ],
    }
)
sunburst_fig = px.sunburst(sunburst_df, names="labels", parents="parents", values="values", title="Sunburst risk composition")
sunburst_fig.update_layout(height=400, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(sunburst_fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("The sunburst chart starts from the overall risk story and breaks it into the main score drivers.")

heatmap_df = pd.DataFrame([list(current_scores.values())], columns=list(current_scores.keys()), index=["Current scan"])
heatmap_fig = px.imshow(heatmap_df, text_auto=True, aspect="auto", title="Current-scan heatmap")
heatmap_fig.update_layout(height=260, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(heatmap_fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("The heatmap turns the current score set into an intensity view for a quick visual read.")

vt_df = pd.DataFrame(
    {
        "Category": ["Malicious", "Other observations"],
        "Count": [
            structured.get("vt_malicious", 0),
            max(structured.get("vt_total", 0) - structured.get("vt_malicious", 0), 0),
        ],
    }
)
vt_fig = px.bar(vt_df, x="Category", y="Count", text="Count", title="Threat intelligence observation split")
vt_fig.update_traces(textposition="outside")
vt_fig.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(vt_fig, use_container_width=True, config=PLOTLY_CONFIG)
st.caption("This chart isolates malicious observations from the rest of the VirusTotal result set.")

if ports:
    port_df = pd.DataFrame(ports)
    if "port" in port_df.columns:
        port_hist = px.histogram(port_df, x="port", title="Open port distribution")
        port_hist.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
        st.plotly_chart(port_hist, use_container_width=True, config=PLOTLY_CONFIG)
        st.caption("This distribution chart shows how the exposed open ports are spread in the current scan.")