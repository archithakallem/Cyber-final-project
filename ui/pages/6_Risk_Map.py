import pandas as pd
import plotly.express as px
import streamlit as st

from ui_utils import PLOTLY_CONFIG, init_state, inject_global_styles, render_logo_header, render_sidebar

st.set_page_config(page_title="CyberScan · Risk Map", page_icon="🌍", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🌍 Risk Map")
render_logo_header("Risk Map", "Future-scope page for geo-risk storytelling and regional threat visualization.", compact=True)

st.info("This module remains a future enhancement and is shown here as a clean concept preview.")
regions = pd.DataFrame(
    {
        "Region": ["North America", "Europe", "Asia-Pacific", "South America", "Middle East & Africa"],
        "Projected Risk Index": [72, 58, 66, 49, 61],
        "Observed Hotspots": [8, 5, 7, 3, 4],
    }
)

fig = px.bar(regions, x="Region", y="Projected Risk Index", title="Illustrative regional risk index", text="Projected Risk Index")
fig.update_traces(textposition="outside")
fig.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(fig, use_container_width=True, config=PLOTLY_CONFIG)

hotspot = px.scatter(regions, x="Observed Hotspots", y="Projected Risk Index", size="Projected Risk Index", hover_name="Region", title="Hotspot intensity concept")
hotspot.update_layout(height=360, margin=dict(l=20, r=20, t=55, b=20))
st.plotly_chart(hotspot, use_container_width=True, config=PLOTLY_CONFIG)
