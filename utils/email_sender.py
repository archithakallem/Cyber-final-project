import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def build_alert_email(target, scores, structured):
    risk = float(scores.get("risk", 0) or 0)
    malicious = int(structured.get("vt_malicious", 0) or 0)
    severity = "Critical" if malicious > 0 else "High"

    findings = []
    if malicious > 0:
        findings.append(
            {
                "name": "VirusTotal malicious detections",
                "severity": "Critical",
                "score": malicious,
                "action": "Validate the indicator immediately and review containment or blocking options.",
            }
        )
    if risk > 70:
        findings.append(
            {
                "name": "Overall risk score",
                "severity": "High" if malicious == 0 else "Critical",
                "score": round(risk, 1),
                "action": "Prioritize a full security review and reduce the main score drivers.",
            }
        )
    if len(structured.get("open_ports", []) or []) > 5:
        findings.append(
            {
                "name": "Open service exposure",
                "severity": "High",
                "score": len(structured.get("open_ports", []) or []),
                "action": "Close or restrict unnecessary externally exposed services.",
            }
        )

    rows = "".join(
        f"<tr><td>{f['name']}</td><td>{f['severity']}</td><td>{f['score']}</td></tr>" for f in findings
    )
    actions = "".join(f"<li><b>{f['name']}:</b> {f['action']}</li>" for f in findings)

    subject = f"[{severity}] CyberScan Alert for {target}"
    html = f"""
    <html>
      <body style="font-family:Arial,sans-serif;color:#111827;line-height:1.5;">
        <h2>CyberScan Automated Alert</h2>
        <p>An automatic alert was triggered because a high-risk or malicious condition was detected for <b>{target}</b>.</p>
        <p><b>Target:</b> {target}<br>
           <b>Overall risk score:</b> {round(risk, 1)}<br>
           <b>Malicious detections:</b> {malicious}</p>

        <h3>High and Critical Findings</h3>
        <table border="1" cellspacing="0" cellpadding="8" style="border-collapse:collapse;width:100%;">
          <thead>
            <tr style="background:#e5eefc;"><th align="left">Name</th><th align="left">Severity</th><th align="left">Score</th></tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>

        <h3>Recommended actions</h3>
        <ul>{actions}</ul>

        <p style="font-size:12px;color:#6b7280;margin-top:20px;">
          This is an automated CyberScan alert generated after the scan completed. Review the findings before taking production action.
        </p>
      </body>
    </html>
    """
    return subject, html


def send_email_report(to_email, subject, html_content):
    sender_email = os.getenv("CYBERSCAN_SMTP_SENDER", "your_email@gmail.com")
    password = os.getenv("CYBERSCAN_SMTP_PASSWORD", "your_app_password")

    if not to_email or sender_email == "your_email@gmail.com" or password == "your_app_password":
        return False, "SMTP not configured"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email
    msg.attach(MIMEText(html_content, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, password)
        server.send_message(msg)

    return True, "Alert sent"
