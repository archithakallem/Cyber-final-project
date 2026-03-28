import pandas as pd
import streamlit as st

from ui_utils import (
    get_support_matrix,
    init_state,
    inject_global_styles,
    render_home_menu,
    render_logo_header,
    render_sidebar,
)

st.set_page_config(page_title="CyberScan · Home", page_icon="🛡️", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🏠 Home")
render_logo_header(
    "CyberScan Home",
    "A clean control center for network exposure discovery, threat-intelligence enrichment, risk scoring, recommendations, historical tracking, and automated alerting.",
)

st.markdown("### What the system does")
st.markdown(
    """
    <div class='cs-soft-card'>
    CyberScan accepts a target once from the left control center, identifies whether the input is a domain, IP address, URL, or file hash, and routes it through the correct scan path. It combines network discovery, external threat intelligence, WHOIS context, and SSL/TLS validation to produce a structured security view that can be reused across summary, analysis, visuals, history, and recommendation pages.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("### Current platform scope")
support_df = pd.DataFrame(get_support_matrix(), columns=["Area", "Count", "Details"])
st.dataframe(support_df, use_container_width=True, hide_index=True)

st.markdown("### Supported targets")
target_df = pd.DataFrame(
    {
        "Target type": ["Domain", "IP address", "URL", "File hash"],
        "How CyberScan handles it": [
            "Uses network discovery, threat-intelligence checks, WHOIS context, and SSL/TLS validation where applicable.",
            "Uses network discovery and external intelligence to assess a direct address-based target.",
            "Uses the full URL for intelligence analysis and extracts the host portion when a network-aware scan is needed.",
            "Uses intelligence analysis only, because hashes represent files rather than live network endpoints.",
        ],
    }
)
st.dataframe(target_df, use_container_width=True, hide_index=True)

st.markdown("### Resource types used")
resource_df = pd.DataFrame(
    {
        "Resource": ["Nmap", "VirusTotal", "WHOIS", "SSL/TLS validation"],
        "Purpose": [
            "Discovers visible open ports and exposed network services for reachable targets.",
            "Adds malicious and total-observation context for domains, IPs, URLs, and file hashes.",
            "Provides ownership and registration-related context for supported domain or IP lookups.",
            "Checks whether transport security is present and usable for applicable web-facing targets.",
        ],
    }
)
st.dataframe(resource_df, use_container_width=True, hide_index=True)

st.markdown("### System flow")
flow_df = pd.DataFrame(
    {
        "Stage": [
            "1. Input capture",
            "2. Target classification",
            "3. Discovery and enrichment",
            "4. Context checks",
            "5. Scoring",
            "6. Alerting and views",
        ],
        "What happens": [
            "Target, backend URL, API key, and email are saved once in the left control center.",
            "The backend identifies whether the input is a domain, IP address, URL, or file hash.",
            "CyberScan runs the relevant Nmap and VirusTotal path based on the detected target type.",
            "WHOIS and SSL/TLS checks add supporting context where they are applicable.",
            "The scoring layer generates exposure, threat, context, and overall risk.",
            "If the result is malicious or high-risk, an email alert can be sent automatically, and the UI pages present the scan story.",
        ],
    }
)
st.dataframe(flow_df, use_container_width=True, hide_index=True)

st.markdown("### Dashboard menu")
st.caption("Save details in the left control center once, then use the left dashboard menu to move through the platform.")
render_home_menu()