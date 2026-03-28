import pandas as pd
import plotly.express as px
import streamlit as st

from ui_utils import PLOTLY_CONFIG, init_state, inject_global_styles, render_logo_header, render_sidebar

st.set_page_config(page_title="CyberScan · Risk Map", page_icon="🌍", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🌍 Risk Map")
render_logo_header(
    "Risk Map",
    "A concept page that presents regional risk storytelling and target-severity mapping in a presentation-friendly format.",
    compact=True,
)

data = st.session_state.get("scan_data")

st.info("This page is a conceptual visualization layer. It helps explain how CyberScan findings could be mapped regionally or grouped by severity in a broader security monitoring scenario.")

# Multi-target mode: use real targets as conceptual risk points
if data and data.get("is_multi_target"):
    comp_df = pd.DataFrame(data.get("comparison", []))

    risk_bands = []
    for _, row in comp_df.iterrows():
        risk = float(row.get("risk", 0) or 0)
        if risk > 70:
            band = "Critical / High"
        elif risk > 40:
            band = "Medium"
        else:
            band = "Low"
        risk_bands.append(band)

    comp_df["Risk Band"] = risk_bands

    st.markdown("### Multi-target severity map")
    st.dataframe(comp_df[["target", "target_type", "risk", "malicious", "open_ports", "Risk Band"]], use_container_width=True, hide_index=True)

    severity_fig = px.scatter(
        comp_df,
        x="open_ports",
        y="risk",
        size="malicious",
        color="Risk Band",
        hover_name="target",
        title="Target severity map",
    )
    severity_fig.update_layout(height=420, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(severity_fig, use_container_width=True, config=PLOTLY_CONFIG)

    band_df = comp_df.groupby("Risk Band", as_index=False).size().rename(columns={"size": "Count"})
    band_fig = px.pie(
        band_df,
        names="Risk Band",
        values="Count",
        title="Distribution of targets by risk band",
        hole=0.45,
    )
    band_fig.update_layout(height=390, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(band_fig, use_container_width=True, config=PLOTLY_CONFIG)

    st.markdown(
        """
        <div class='cs-soft-card'>
        <b>How to explain this page</b><br>
        Even though CyberScan does not use real geolocation in the current model, this page shows how scanned targets can be grouped into severity zones.
        It helps present risk concentration, critical targets, and the overall spread of issues across a broader monitored environment.
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    regions = pd.DataFrame(
        {
            "Region": ["North America", "Europe", "Asia-Pacific", "South America", "Middle East & Africa"],
            "Projected Risk Index": [72, 58, 66, 49, 61],
            "Observed Hotspots": [8, 5, 7, 3, 4],
        }
    )

    st.markdown("### Conceptual regional view")
    fig = px.bar(
        regions,
        x="Region",
        y="Projected Risk Index",
        title="Illustrative regional risk index",
        text="Projected Risk Index",
    )
    fig.update_traces(textposition="outside")
    fig.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)

    hotspot = px.scatter(
        regions,
        x="Observed Hotspots",
        y="Projected Risk Index",
        size="Projected Risk Index",
        hover_name="Region",
        title="Hotspot intensity concept",
    )
    hotspot.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
    st.plotly_chart(hotspot, use_container_width=True, config=PLOTLY_CONFIG)

    st.markdown(
        """
        <div class='cs-soft-card'>
        <b>Why this page exists</b><br>
        Risk Map is designed as a future-facing visualization layer.
        It shows how CyberScan findings could be projected into regional or severity-based monitoring views for larger environments.
        </div>
        """,
        unsafe_allow_html=True,
    )