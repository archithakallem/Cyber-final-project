from fastapi import APIRouter, HTTPException, Query

from app.database import get_history, save_scan
from app.processor import process_data
from app.scanner import detect_target_type, run_nmap_scan, run_virustotal_scan
from app.scoring import calculate_scores
from utils.email_sender import build_alert_email, send_email_report

router = APIRouter()


def get_network_target(target: str, target_type: str) -> str:
    """
    Nmap should receive only a host/IP.
    If the user gives a URL, strip protocol and path.
    """
    if target_type == "url":
        cleaned = target.replace("https://", "").replace("http://", "")
        cleaned = cleaned.split("/")[0]
        return cleaned
    return target


@router.get("/scan/{target:path}")
def scan(
    target: str,
    api_key: str = Query(...),
    email: str | None = Query(default=None)
):
    try:
        target_type = detect_target_type(target)
        network_target = get_network_target(target, target_type)

        # Nmap does not apply to file hashes
        if target_type == "hash":
            nmap_data = []
        else:
            nmap_data = run_nmap_scan(network_target)

        vt_data = run_virustotal_scan(target, api_key, target_type)

        structured = process_data(nmap_data, vt_data)
        scores = calculate_scores(structured)

        save_scan(target, scores)

        alert_triggered = bool(
            structured.get("vt_malicious", 0) > 0
            or float(scores.get("risk", 0)) > 70
        )

        email_status = "Not triggered"
        if alert_triggered and email:
            subject, html = build_alert_email(target, scores, structured)
            sent, email_status = send_email_report(email, subject, html)
            if not sent:
                email_status = f"Alert qualified but not sent: {email_status}"

        return {
            "target": target,
            "target_type": target_type,
            "data": structured,
            "scores": scores,
            "alert_triggered": alert_triggered,
            "email_status": email_status,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/history/{target:path}")
def history(target: str):
    try:
        rows = get_history(target)
        return {"target": target, "history": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"History fetch failed: {str(e)}")