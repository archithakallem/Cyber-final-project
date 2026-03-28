import pandas as pd
import plotly.express as px
import streamlit as st

from ui_utils import (
    PLOTLY_CONFIG,
    finding_cards,
    init_state,
    inject_global_styles,
    render_logo_header,
    render_sidebar,
    safe_round,
)

st.set_page_config(page_title="CyberScan · Analysis", page_icon="🔎", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🔎 Analysis")
render_logo_header(
    "Deep Analysis",
    "Review network evidence, threat signals, and short explanations of what the result means.",
    compact=True,
)

data = st.session_state.get("scan_data")
if not data:
    st.warning("Run a scan from the Summary page first.")
    st.stop()

# ---------------- MULTI TARGET MODE ----------------
if data.get("is_multi_target"):
    comp_df = pd.DataFrame(data.get("comparison", []))

    st.markdown("### Multi-target analysis")
    st.dataframe(comp_df, use_container_width=True, hide_index=True)

    highest_risk = comp_df.sort_values("risk", ascending=False).iloc[0]
    highest_ports = comp_df.sort_values("open_ports", ascending=False).iloc[0]
    highest_mal = comp_df.sort_values("malicious", ascending=False).iloc[0]

    st.markdown(
        f"""
        <div class='cs-soft-card'>
        <b>Highest-risk target:</b> {highest_risk['target']} with risk {safe_round(highest_risk['risk'])}.<br>
        <b>Highest exposure:</b> {highest_ports['target']} with {int(highest_ports['open_ports'])} open port(s).<br>
        <b>Highest malicious signal:</b> {highest_mal['target']} with {int(highest_mal['malicious'])} malicious detection(s).<br>
        This helps identify whether the most concerning target is being driven by exposure, threat reputation, or both.
        </div>
        """,
        unsafe_allow_html=True,
    )

    risk_fig = px.bar(
        comp_df,
        x="target",
        y="risk",
        color="target_type",
        text="risk",
        title="Risk ranking across targets",
    )
    risk_fig.update_traces(textposition="outside")
    risk_fig.update_layout(height=380, yaxis_range=[0, 110], margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(risk_fig, use_container_width=True, config=PLOTLY_CONFIG)

    exp_fig = px.bar(
        comp_df,
        x="target",
        y=["open_ports", "malicious"],
        barmode="group",
        title="Exposure and malicious signals across targets",
    )
    exp_fig.update_layout(height=380, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(exp_fig, use_container_width=True, config=PLOTLY_CONFIG)

    st.markdown("### Analyst summary")
    st.info(
        "In multi-target mode, the most important comparison is whether risk is being driven by high open-port exposure, high malicious detections, or a weaker context score. This view supports prioritization during presentation or review."
    )
    st.stop()

# ---------------- SINGLE TARGET MODE ----------------
scores = data.get("scores", {})
structured = data.get("data", {})
ports = structured.get("open_ports", []) or []
vt_malicious = int(structured.get("vt_malicious", 0) or 0)
vt_total = int(structured.get("vt_total", 0) or 0)

k1, k2, k3, k4 = st.columns(4)
k1.metric("Open Ports", len(ports))
k2.metric("Malicious Flags", vt_malicious)
k3.metric("Threat Lookups", vt_total)
k4.metric("Context", safe_round(scores.get("context", 0)))

st.markdown("### Network analysis")
if ports:
    df_ports = pd.DataFrame(ports).rename(columns={"port": "Port", "state": "State"})
    state_choices = sorted(df_ports["State"].dropna().unique().tolist()) if "State" in df_ports.columns else []
    selected_states = st.multiselect("Filter by port state", state_choices, default=state_choices)
    filtered_ports = df_ports[df_ports["State"].isin(selected_states)] if selected_states else df_ports
    st.dataframe(filtered_ports, use_container_width=True, hide_index=True)

    port_fig = px.bar(filtered_ports, x="Port", color="State", title="Open port view by state")
    port_fig.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(port_fig, use_container_width=True, config=PLOTLY_CONFIG)
else:
    st.success("No open ports were found in this scan.")

st.markdown("### Threat intelligence")
ratio = safe_round((vt_malicious / vt_total * 100) if vt_total else 0)
threat_df = pd.DataFrame(
    {
        "Category": ["Malicious", "Other / clean"],
        "Count": [vt_malicious, max(vt_total - vt_malicious, 0)],
    }
)

threat_fig = px.pie(threat_df, names="Category", values="Count", title="Threat signal composition", hole=0.45)
threat_fig.update_layout(height=390, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(threat_fig, use_container_width=True, config=PLOTLY_CONFIG)

st.markdown(
    f"<div class='cs-soft-card'><b>Brief explanation</b><br>VirusTotal reported {vt_malicious} malicious detection(s) out of {vt_total} observations, which gives a threat ratio of {ratio}%. This view helps separate a purely exposed target from a target that is also showing external threat reputation signals.</div>",
    unsafe_allow_html=True,
)

st.markdown("### Key findings")
for title, body in finding_cards(structured, scores):
    with st.expander(title, expanded=True):
        st.write(body)

st.markdown("### Interactive analyst summary")
focus = st.selectbox("Focus the explanation on", ["Overall picture", "Exposure", "Threat", "Context"])
if focus == "Exposure":
    st.info("Exposure reflects how many externally visible services were found. More visible services generally mean a larger attack surface and more points that need hardening.")
elif focus == "Threat":
    st.info("Threat reflects the external reputation signal contributed by VirusTotal. Malicious detections raise priority because the target is not only visible but also externally concerning.")
elif focus == "Context":
    st.info("Context estimates how hardened the target looks in the current model. Better SSL and security-header posture would raise this number and improve the overall story.")
else:
    st.info("CyberScan combines exposure, threat, and context so the result is not driven by one signal alone. This helps the dashboard tell a fuller story instead of only showing raw technical data.")