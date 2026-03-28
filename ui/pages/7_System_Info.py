import pandas as pd
import streamlit as st

from ui_utils import get_support_matrix, init_state, inject_global_styles, render_logo_header, render_sidebar

st.set_page_config(page_title="CyberScan · System Info", page_icon="🖥", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🖥️ System Info")
render_logo_header(
    "System Info",
    "What powers the platform today, what target types it handles, how multi-target mode works, and how alerting and history behave.",
    compact=True,
)

features = pd.DataFrame(
    {
        "Capability": [
            "Single-entry control center",
            "Nmap-based exposure discovery",
            "VirusTotal threat enrichment",
            "WHOIS contextual support",
            "SSL/TLS validation support",
            "Structured processing layer",
            "Score engine",
            "SQLite history tracking",
            "Automated email alerting",
            "Multi-target comparison mode",
        ],
        "System role": [
            "Collects target, backend URL, API key, and email once from the left panel.",
            "Identifies visible open ports that shape exposure.",
            "Adds malicious and total-detection context from external intelligence.",
            "Adds ownership and registration context for supported target types.",
            "Adds secure-communication checks for applicable web-facing targets.",
            "Normalizes raw scan outputs into reusable fields for the UI.",
            "Calculates exposure, threat, context, and overall risk.",
            "Stores each run in the backend database with timestamp and scores.",
            "Sends an HTML email automatically when the result is high-risk or malicious.",
            "Splits comma-separated targets, scans them individually, and produces a comparison dataset.",
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
    Data flow: Input → Detect target type → Scan → Enrich → Process → Score → Save → Alert → Visualize.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class='cs-soft-card'><b>Supported targets</b><br>
    Domain, IP address, URL, and file hash are handled through different logic paths.
    Network-aware scans such as Nmap apply only to live network targets, while intelligence-only targets like file hashes skip that stage.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class='cs-soft-card'><b>Multi-target mode</b><br>
    When the user enters comma-separated targets, the backend scans each target separately and returns both individual results and a comparison view.
    Summary, Analysis, Visuals, Recommendations, and Risk Map then adapt their content to explain the differences between those targets.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class='cs-soft-card'><b>Alerting and delivery</b><br>
    CyberScan triggers an alert when malicious detections are present or the overall risk is greater than 70.
    Triggering an alert and delivering an email are separate outcomes: delivery still depends on SMTP sender configuration.
    </div>
    """,
    unsafe_allow_html=True,
)