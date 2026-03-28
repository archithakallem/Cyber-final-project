import pandas as pd
import streamlit as st

from ui_utils import get_support_matrix, init_state, inject_global_styles, render_logo_header, render_sidebar

st.set_page_config(page_title="CyberScan · System Info", page_icon="🖥", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🖥️ System Info")
render_logo_header("System Info", "What powers the platform today, what target types it handles, and how history and alerting work.", compact=True)

features = pd.DataFrame(
    {
        "Capability": [
            "Single-entry control center",
            "Nmap-based exposure discovery",
            "VirusTotal threat enrichment",
            "Structured processing layer",
            "Score engine",
            "SQLite history tracking",
            "Automated email alerting",
        ],
        "System role": [
            "Collects target, backend URL, API key, and email once from the left panel.",
            "Identifies visible open ports that shape exposure.",
            "Adds malicious and total-detection context from external intelligence.",
            "Normalizes raw scan outputs into reusable fields for the UI.",
            "Calculates exposure, threat, context, and overall risk.",
            "Stores each run in the backend database with timestamp and scores.",
            "Sends an HTML email automatically when the result is high-risk or malicious.",
        ],
    }
)
st.dataframe(features, use_container_width=True, hide_index=True)

support_df = pd.DataFrame(get_support_matrix(), columns=["Area", "Count", "Details"])
st.dataframe(support_df, use_container_width=True, hide_index=True)

st.markdown(
    """
    <div class='cs-soft-card'><b>Architecture summary</b><br>
    Frontend: Streamlit multipage UI acts as the operator console.<br>
    Backend: FastAPI coordinates scanner, processor, scoring, database, and alert logic.<br>
    Data flow: Input → Scan → Enrich → Process → Score → Save → Alert → Visualize.
    </div>
    """,
    unsafe_allow_html=True,
)
