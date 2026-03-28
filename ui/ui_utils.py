from __future__ import annotations

import math
from typing import List, Tuple

import streamlit as st


PAGE_MAP = {
    "🏠 Home": "app.py",
    "📊 Summary": "pages/1_Summary.py",
    "🔎 Analysis": "pages/2_Analysis.py",
    "📈 Visuals": "pages/3_Visuals.py",
    "📅 History": "pages/4_History.py",
    "🛡️ Recommendations": "pages/5_Recommendations.py",
    "🌍 Risk Map": "pages/6_Risk_Map.py",
    "🖥️ System Info": "pages/7_System_Info.py",
}

PLOTLY_CONFIG = {
    "displayModeBar": True,
    "displaylogo": False,
    "responsive": True,
    "scrollZoom": True,
}


def init_state():
    defaults = {
        "target": "",
        "api_key": "",
        "email": "",
        "scan_data": None,
        "backend_url": "http://127.0.0.1:8000",
        "history_backend": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def inject_global_styles():
    st.markdown(
        """
        <style>
        #MainMenu, footer, header {visibility: hidden;}
        [data-testid="stSidebarNav"] {display: none;}
        .block-container {
            max-width: 1180px;
            padding-top: 1rem;
            padding-bottom: 2rem;
        }
        .stPlotlyChart, .element-container iframe {
            border-radius: 18px;
        }
        .cs-hero {
            padding: 1.25rem 1.35rem;
            border-radius: 24px;
            background: linear-gradient(135deg, rgba(14,165,233,0.16), rgba(99,102,241,0.14), rgba(16,185,129,0.10));
            border: 1px solid rgba(148,163,184,0.16);
            box-shadow: 0 18px 40px rgba(15,23,42,0.14);
            margin-bottom: 1rem;
        }
        .cs-compact {
            padding: 0.95rem 1.1rem;
            border-radius: 20px;
            background: linear-gradient(180deg, rgba(15,23,42,0.38), rgba(15,23,42,0.25));
            border: 1px solid rgba(148,163,184,0.14);
            margin-bottom: 1rem;
        }
        .cs-logo-wrap {
            display:flex;
            align-items:center;
            gap:0.95rem;
            min-height:72px;
            overflow: visible;
        }
        .cs-logo {
            min-width:64px;
            width:64px;
            height:64px;
            border-radius:18px;
            background: radial-gradient(circle at 28% 28%, #67e8f9, #2563eb 56%, #0f172a 100%);
            display:inline-flex;
            align-items:center;
            justify-content:center;
            position:relative;
            box-shadow:0 12px 28px rgba(37,99,235,0.28);
            flex-shrink:0;
        }
        .cs-logo:before {
            content:'';
            width:28px;
            height:34px;
            border-radius:14px 14px 10px 10px;
            border:2px solid rgba(255,255,255,0.95);
            border-bottom-width:4px;
            clip-path: polygon(50% 0%, 100% 18%, 100% 65%, 50% 100%, 0% 65%, 0% 18%);
        }
        .cs-logo:after {
            content:'';
            position:absolute;
            width:18px;
            height:18px;
            border-radius:999px;
            border:2px solid rgba(255,255,255,0.9);
            box-shadow:0 0 0 6px rgba(255,255,255,0.08);
        }
        .cs-title {
            margin:0;
            font-size:1.9rem;
            line-height:1.15;
            font-weight:800;
            letter-spacing:-0.02em;
        }
        .cs-compact-title {
            margin:0;
            font-size:1.35rem;
            line-height:1.2;
            font-weight:800;
        }
        .cs-subtitle {
            margin-top:0.25rem;
            color:#cbd5e1;
            font-size:0.96rem;
            line-height:1.45;
        }
        .cs-soft-card {
            padding: 0.95rem 1rem;
            border-radius: 18px;
            border: 1px solid rgba(148,163,184,0.14);
            background: rgba(255,255,255,0.02);
            margin-bottom: 0.85rem;
        }
        .cs-menu-card {
            padding: 0.9rem 1rem;
            border-radius: 16px;
            border: 1px solid rgba(59,130,246,0.18);
            background: linear-gradient(180deg, rgba(30,41,59,0.38), rgba(15,23,42,0.28));
            margin-bottom: 0.75rem;
        }
        .cs-chip {
            display:inline-block;
            padding:0.25rem 0.6rem;
            border-radius:999px;
            background:rgba(59,130,246,0.15);
            border:1px solid rgba(96,165,250,0.25);
            margin:0.12rem 0.18rem 0.12rem 0;
            font-size:0.82rem;
        }
        .cs-mini {color:#94a3b8; font-size:0.86rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_logo_header(title: str, subtitle: str, compact: bool = False):
    wrapper = "cs-compact" if compact else "cs-hero"
    title_cls = "cs-compact-title" if compact else "cs-title"
    st.markdown(
        f"""
        <div class="{wrapper}">
            <div class="cs-logo-wrap">
                <div class="cs-logo"></div>
                <div style="min-width:0;">
                    <p class="{title_cls}">{title}</p>
                    <div class="cs-subtitle">{subtitle}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar(current_page: str = "🏠 Home"):
    with st.sidebar:
        st.markdown("## Control Center")
        with st.form("workspace_form"):
            target = st.text_input("Target", value=st.session_state.get("target", ""), placeholder="scanme.nmap.org")
            backend_url = st.text_input("Backend URL", value=st.session_state.get("backend_url", "http://127.0.0.1:8000"))
            api_key = st.text_input("VirusTotal API key", value=st.session_state.get("api_key", ""), type="password")
            email = st.text_input("Alert email", value=st.session_state.get("email", ""), placeholder="team@example.com")
            save = st.form_submit_button("Save details", use_container_width=True, type="primary")
        if save:
            st.session_state.target = target.strip()
            st.session_state.backend_url = backend_url.strip() or "http://127.0.0.1:8000"
            st.session_state.api_key = api_key.strip()
            st.session_state.email = email.strip()
            st.rerun()

        st.caption("These values are shared across every page through Streamlit session state.")
        st.divider()
        st.markdown("### Current workspace")
        st.write(f"**Target:** {st.session_state.get('target') or 'Not set'}")
        st.write(f"**Email:** {st.session_state.get('email') or 'Not set'}")
        st.write(f"**API key:** {'Configured' if st.session_state.get('api_key') else 'Not set'}")
        st.write(f"**Backend:** {st.session_state.get('backend_url') or 'Not set'}")
        if st.button("Clear latest scan", use_container_width=True):
            st.session_state.scan_data = None
            st.rerun()
        st.divider()
        with st.expander("Dashboard Menu", expanded=True):
            selected = st.selectbox("Navigate to", list(PAGE_MAP.keys()), index=list(PAGE_MAP.keys()).index(current_page))
            if selected != current_page:
                st.switch_page(PAGE_MAP[selected])
            st.caption("Use this menu to move through the dashboard pages.")


def render_home_menu():
    st.markdown("### Dashboard Menu")
    items = [
        ("📊 Summary", "Run the scan and review the main score story."),
        ("🔎 Analysis", "Inspect ports, threat details, and guided findings."),
        ("📈 Visuals", "Open the chart lab for comparisons and breakdowns."),
        ("📅 History", "Track how scores change across saved scans."),
        ("🛡️ Recommendations", "Turn findings into next-step actions."),
        ("🌍 Risk Map", "Preview future geo-risk storytelling."),
        ("🖥️ System Info", "See what the platform uses and supports today."),
    ]
    for title, desc in items:
        st.markdown(f"<div class='cs-menu-card'><b>{title}</b><br><span class='cs-mini'>{desc}</span></div>", unsafe_allow_html=True)


def require_scan_inputs(require_email: bool = False):
    missing = []
    if not st.session_state.get("target"):
        missing.append("target")
    if not st.session_state.get("api_key"):
        missing.append("api key")
    if require_email and not st.session_state.get("email"):
        missing.append("email")
    if missing:
        st.warning("Set " + ", ".join(missing) + " in the left Control Center first.")
        st.stop()


def get_risk_label(risk_value: float):
    if risk_value >= 80:
        return "Critical Risk", "🛑"
    if risk_value > 70:
        return "High Risk", "🚨"
    if risk_value > 40:
        return "Medium Risk", "⚠️"
    return "Low Risk", "✅"


def safe_round(value, digits: int = 1):
    try:
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return 0
        return round(float(value), digits)
    except Exception:
        return 0


def summarise_findings(structured: dict, scores: dict):
    ports = structured.get("open_ports", []) or []
    malicious = int(structured.get("vt_malicious", 0) or 0)
    vt_total = int(structured.get("vt_total", 0) or 0)
    risk = safe_round(scores.get("risk", 0))
    exposure = safe_round(scores.get("exposure", 0))
    context = safe_round(scores.get("context", 0))
    lines = [
        f"CyberScan discovered <b>{len(ports)}</b> externally visible port(s), which produced an exposure score of <b>{exposure}</b>.",
        f"VirusTotal contributed <b>{malicious}</b> malicious detection(s) out of <b>{vt_total}</b> observed checks in this model.",
        f"The current contextual hardening estimate is <b>{context}</b>, based on the present SSL and security-header placeholders.",
        f"The combined overall risk score for this run is <b>{risk}</b>.",
    ]
    if malicious > 0:
        lines.append("Because malicious detections were present, the platform would treat this asset as alert-worthy when email alerting is configured.")
    elif risk > 70:
        lines.append("Even without a direct malicious flag, the score profile is high enough to justify rapid review and an automated alert.")
    else:
        lines.append("This run remains below the automatic email-alert threshold in the current ruleset.")
    return lines


def finding_cards(structured: dict, scores: dict) -> List[Tuple[str, str]]:
    ports = structured.get("open_ports", []) or []
    malicious = int(structured.get("vt_malicious", 0) or 0)
    vt_total = int(structured.get("vt_total", 0) or 0)
    risk = float(scores.get("risk", 0) or 0)
    findings = []
    if ports:
        findings.append((
            "Port exposure finding",
            f"The scan identified {len(ports)} open port(s). Each visible service increases the external attack surface, so every open service should have a clear business purpose and strong access controls.",
        ))
    else:
        findings.append((
            "Port exposure finding",
            "The scan did not identify open ports in the current fast-scan view. That is a positive sign, but it is still a point-in-time result rather than a permanent guarantee.",
        ))
    if vt_total:
        findings.append((
            "Threat-intelligence finding",
            f"VirusTotal reported {malicious} malicious result(s) across {vt_total} observations. This gives external reputation context that complements the technical scan evidence.",
        ))
    findings.append((
        "Overall risk finding",
        f"The combined risk score is {safe_round(risk)}. CyberScan interprets this score as {get_risk_label(risk)[0].lower()}, which determines how urgently the result should be reviewed.",
    ))
    return findings


def get_support_matrix():
    return [
        (
            "Scanning resources used",
            "4 resources",
            "Nmap for port discovery, VirusTotal for threat intelligence, WHOIS for ownership and registration context, and SSL/TLS validation for transport-security checks.",
        ),
        (
            "Supported target types",
            "4 target types",
            "CyberScan accepts domain, IP address, URL, and file hash inputs in the current scan flow.",
        ),
        (
            "Network-capable targets",
            "3 types",
            "Domain, IP address, and URL can go through the network-aware path. File hashes are intelligence-only targets and do not use Nmap.",
        ),
        (
            "Alerting behavior",
            "Conditional",
            "Email alerts are triggered when malicious detections are present or when the overall risk score is greater than 70 and an email address is provided.",
        ),
    ]