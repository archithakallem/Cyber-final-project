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
    "A richer visual lab with comparison charts and analysis charts for both single-target and multi-target scans.",
    compact=True,
)

data = st.session_state.get("scan_data")
if not data:
    st.warning("Run a scan from the Summary page first.")
    st.stop()

# ---------------- MULTI TARGET MODE ----------------
if data.get("is_multi_target"):
    comp_df = pd.DataFrame(data.get("comparison", []))

    if comp_df.empty:
        st.warning("No comparison data available.")
        st.stop()

    st.info("Multi-target mode: these charts compare all scanned targets and help show which target is driving higher risk.")

    # 1. Bar chart
    fig1 = px.bar(
        comp_df,
        x="target",
        y="risk",
        color="target_type",
        text="risk",
        title="Overall risk by target",
    )
    fig1.update_traces(textposition="outside")
    fig1.update_layout(height=420, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig1, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("This bar chart compares the overall risk score across all scanned targets.")

    # 2. Line chart
    fig2 = px.line(
        comp_df,
        x="target",
        y=["exposure", "threat", "context", "risk"],
        markers=True,
        title="Score profile across targets",
    )
    fig2.update_layout(height=430, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig2, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("This line chart shows how exposure, threat, context, and risk vary from one target to another.")

    # 3. Grouped chart for malicious + open ports
    fig3 = px.bar(
        comp_df,
        x="target",
        y=["malicious", "open_ports"],
        barmode="group",
        title="Malicious detections and open ports by target",
    )
    fig3.update_layout(height=400, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig3, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("This grouped chart contrasts threat intelligence and exposure indicators for each target.")

    # 4. Scatter / bubble chart
    fig4 = px.scatter(
        comp_df,
        x="open_ports",
        y="risk",
        size="malicious",
        color="target_type",
        hover_name="target",
        title="Exposure vs risk vs malicious activity",
    )
    fig4.update_layout(height=430, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig4, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("Targets farther up and to the right are generally more concerning, especially when the bubble is larger.")

    # 5. Heatmap
    heatmap_input = comp_df.set_index("target")[["exposure", "threat", "context", "risk"]]
    fig5 = px.imshow(
        heatmap_input,
        text_auto=True,
        aspect="auto",
        title="Multi-target score heatmap",
    )
    fig5.update_layout(height=380, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig5, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("The heatmap makes it easier to spot which target is highest in each scoring dimension.")

    # 6. Pie chart
    pie_df = pd.DataFrame(
        {
            "Target": comp_df["target"],
            "Risk": comp_df["risk"],
        }
    )
    fig6 = px.pie(
        pie_df,
        names="Target",
        values="Risk",
        title="Risk contribution share across targets",
    )
    fig6.update_layout(height=420, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig6, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("This pie chart shows how much each target contributes to the total combined risk picture.")

    # 7. Donut chart
    fig7 = px.pie(
        pie_df,
        names="Target",
        values="Risk",
        title="Risk share donut view",
        hole=0.45,
    )
    fig7.update_layout(height=420, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig7, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("The donut chart gives the same comparison in a compact circular form.")

    # 8. Sunburst
    sunburst_df = pd.DataFrame(
        {
            "labels": (
                ["All Targets"]
                + comp_df["target"].tolist()
                + [f"{row['target']} · Risk" for _, row in comp_df.iterrows()]
            ),
            "parents": (
                [""]
                + ["All Targets"] * len(comp_df)
                + comp_df["target"].tolist()
            ),
            "values": (
                [max(comp_df["risk"].sum(), 1)]
                + comp_df["risk"].tolist()
                + comp_df["risk"].tolist()
            ),
        }
    )
    fig8 = px.sunburst(
        sunburst_df,
        names="labels",
        parents="parents",
        values="values",
        title="Sunburst comparison across targets",
    )
    fig8.update_layout(height=430, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig8, use_container_width=True, config=PLOTLY_CONFIG)
    st.caption("The sunburst view shows the overall multi-target picture and how each target contributes to it.")

    st.markdown("### Quick analyst interpretation")
    highest = comp_df.sort_values("risk", ascending=False).iloc[0]
    st.markdown(
        f"""
        <div class='cs-soft-card'>
        The most critical target in this run is <b>{highest['target']}</b>, with a risk score of <b>{safe_round(highest['risk'])}</b>.
        Use the charts above to explain whether that result is being driven more by open-port exposure, malicious detections, or both.
        This mode is useful for demonstrating comparison, prioritization, and relative security posture across multiple targets.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# ---------------- SINGLE TARGET MODE ----------------
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

score_df = pd.DataFrame(
    {"Metric": list(current_scores.keys()), "Score": list(current_scores.values())}
)

# Bar chart
fig = px.bar(score_df, x="Metric", y="Score", text="Score", title="Current score overview")
fig.update_traces(textposition="outside")
fig.update_layout(height=420, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)

# Pie chart
pie_fig = px.pie(
    values=[current_scores["Exposure"], current_scores["Threat"], current_scores["Context"]],
    names=["Exposure", "Threat", "Context"],
    title="Contribution distribution",
)
pie_fig.update_layout(height=390, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(pie_fig, use_container_width=True, config=PLOTLY_CONFIG)

# Donut chart
donut_fig = px.pie(
    values=[current_scores["Exposure"], current_scores["Threat"], current_scores["Context"]],
    names=["Exposure", "Threat", "Context"],
    title="Contribution donut view",
    hole=0.45,
)
donut_fig.update_layout(height=390, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(donut_fig, use_container_width=True, config=PLOTLY_CONFIG)

# Line chart
line_df = pd.DataFrame(
    {"Metric": list(current_scores.keys()), "Score": list(current_scores.values())}
)
line_fig = px.line(line_df, x="Metric", y="Score", markers=True, title="Metric line view")
line_fig.update_layout(height=340, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(line_fig, use_container_width=True, config=PLOTLY_CONFIG)

# Sunburst
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

# Radar
radar = go.Figure()
radar.add_trace(
    go.Scatterpolar(
        r=list(current_scores.values()) + [current_scores["Exposure"]],
        theta=["Exposure", "Threat", "Context", "Risk", "Exposure"],
        fill="toself",
        name="Current scan",
    )
)
radar.update_layout(
    title="Radar view",
    polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
    height=430,
    margin=dict(l=20, r=20, t=55, b=20),
)
st.plotly_chart(radar, use_container_width=True, config=PLOTLY_CONFIG)

# Heatmap
heatmap_input = pd.DataFrame([current_scores], index=["Current scan"])
heatmap_fig = px.imshow(
    heatmap_input,
    text_auto=True,
    aspect="auto",
    title="Current scan heatmap",
)
heatmap_fig.update_layout(height=260, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(heatmap_fig, use_container_width=True, config=PLOTLY_CONFIG)

# Port distribution
if ports:
    port_df = pd.DataFrame(ports)
    if "port" in port_df.columns:
        port_hist = px.histogram(port_df, x="port", title="Open port distribution")
        port_hist.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
        st.plotly_chart(port_hist, use_container_width=True, config=PLOTLY_CONFIG)