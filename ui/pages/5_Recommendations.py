import pandas as pd
import streamlit as st

from ui_utils import init_state, inject_global_styles, render_logo_header, render_sidebar, safe_round

st.set_page_config(page_title="CyberScan · Recommendations", page_icon="🛡️", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🛡️ Recommendations")
render_logo_header("Smart Recommendations", "Practical actions generated from the scan and brief explanations of why each one matters.", compact=True)

data = st.session_state.get("scan_data")
if not data:
    st.warning("Run a scan from the Summary page first.")
    st.stop()

structured = data.get("data", {})
scores = data.get("scores", {})
recommendations = []
ports_count = len(structured.get("open_ports", []) or [])
vt_malicious = int(structured.get("vt_malicious", 0) or 0)
context = float(scores.get("context", 0) or 0)
risk = float(scores.get("risk", 0) or 0)

if ports_count > 5:
    recommendations.append(("High", "Reduce exposed services", "A high port count increases the attack surface.", "Close or restrict services that are not required externally."))
elif ports_count > 0:
    recommendations.append(("Medium", "Validate service necessity", "A smaller set of open ports is still visible.", "Confirm that each service is expected and protected with access controls."))

if vt_malicious > 0:
    recommendations.append(("Critical", "Investigate threat signal", "External intelligence flagged malicious activity.", "Validate the indicator, review the asset, and consider containment if confirmed."))

if context < 60:
    recommendations.append(("Medium", "Improve hardening posture", "The context score is weaker than ideal.", "Strengthen SSL validation and increase security-header coverage."))

if risk > 70:
    recommendations.append(("Critical", "Prioritize full review", "The overall score is high.", "Escalate the target for immediate security review and remediation planning."))
elif risk > 40:
    recommendations.append(("Medium", "Plan remediation", "The result is moderate.", "Focus first on the drivers pushing exposure and threat upward."))

if not recommendations:
    recommendations.append(("Good", "Maintain current controls", "No dominant issue was found in the current model.", "Continue monitoring and keep preventive controls up to date."))

for idx, (priority, title, reason, action) in enumerate(recommendations, start=1):
    st.markdown(
        f"<div class='cs-soft-card'><b>{idx}. {title}</b><br><span class='cs-mini'>Priority: {priority}</span><br><b>Why:</b> {reason}<br><b>Suggested action:</b> {action}</div>",
        unsafe_allow_html=True,
    )

rec_df = pd.DataFrame(recommendations, columns=["Priority", "Recommendation", "Why", "Action"])
st.dataframe(rec_df, use_container_width=True, hide_index=True)

st.markdown(
    f"<div class='cs-soft-card'><b>Why these recommendations were generated</b><br>CyberScan observed {ports_count} open port(s), {vt_malicious} malicious detection(s), a context score of {safe_round(context)}, and an overall risk score of {safe_round(risk)}. Those values drove the action list above.</div>",
    unsafe_allow_html=True,
)
