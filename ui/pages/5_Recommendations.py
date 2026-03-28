import pandas as pd
import streamlit as st

from ui_utils import init_state, inject_global_styles, render_logo_header, render_sidebar, safe_round

st.set_page_config(page_title="CyberScan · Recommendations", page_icon="🛡️", layout="wide")
init_state()
inject_global_styles()
render_sidebar("🛡️ Recommendations")
render_logo_header(
    "Smart Recommendations",
    "Practical actions generated from the scan, along with short explanations of why they matter and what to do next.",
    compact=True,
)

data = st.session_state.get("scan_data")
if not data:
    st.warning("Run a scan from the Summary page first.")
    st.stop()

# ---------------- MULTI TARGET MODE ----------------
if data.get("is_multi_target"):
    comp_df = pd.DataFrame(data.get("comparison", []))

    st.markdown("### Multi-target recommendation view")
    st.dataframe(comp_df, use_container_width=True, hide_index=True)

    recommendations = []
    for _, row in comp_df.iterrows():
        target = row["target"]
        risk = float(row.get("risk", 0) or 0)
        malicious = int(row.get("malicious", 0) or 0)
        ports = int(row.get("open_ports", 0) or 0)

        if malicious > 0:
            recommendations.append(
                (
                    "Critical",
                    target,
                    "Investigate threat signal",
                    "External intelligence flagged malicious activity for this target.",
                    "Validate the indicator immediately and review containment or blocking options.",
                )
            )

        if ports > 5:
            recommendations.append(
                (
                    "High",
                    target,
                    "Reduce exposed services",
                    "A larger number of open ports increases the visible attack surface.",
                    "Close or restrict services that are not required externally.",
                )
            )

        if risk > 70:
            recommendations.append(
                (
                    "Critical",
                    target,
                    "Prioritize full security review",
                    "The overall risk score is high for this target.",
                    "Escalate this target for immediate review and remediation planning.",
                )
            )
        elif risk > 40:
            recommendations.append(
                (
                    "Medium",
                    target,
                    "Plan remediation",
                    "The overall result is moderate and should still be improved.",
                    "Focus first on the factors driving exposure and threat upward.",
                )
            )

    if not recommendations:
        recommendations.append(
            (
                "Good",
                "All scanned targets",
                "Maintain current controls",
                "No dominant issue was found in the current multi-target run.",
                "Continue monitoring and keep preventive controls updated.",
            )
        )

    rec_df = pd.DataFrame(
        recommendations,
        columns=["Priority", "Target", "Recommendation", "Why", "Action"],
    )

    for idx, row in rec_df.iterrows():
        st.markdown(
            f"""
            <div class='cs-soft-card'>
            <b>{idx + 1}. {row['Recommendation']}</b><br>
            <span class='cs-mini'>Priority: {row['Priority']} | Target: {row['Target']}</span><br>
            <b>Why:</b> {row['Why']}<br>
            <b>Suggested action:</b> {row['Action']}
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.dataframe(rec_df, use_container_width=True, hide_index=True)

    st.markdown(
        """
        <div class='cs-soft-card'>
        <b>How to present this page</b><br>
        In multi-target mode, recommendations help prioritize which target should be handled first.
        A target with malicious detections should be reviewed before one that is only moderately exposed,
        even if both appear in the same comparison run.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# ---------------- SINGLE TARGET MODE ----------------
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