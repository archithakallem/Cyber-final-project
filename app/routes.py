from fastapi import APIRouter, HTTPException, Query

from app.database import get_history, save_scan
from app.processor import process_data
from app.scanner import detect_target_type, run_nmap_scan, run_virustotal_scan
from app.scoring import calculate_scores
from utils.email_sender import build_alert_email, send_email_report

router = APIRouter()


def get_network_target(target: str, target_type: str) -> str:
    if target_type == "url":
        cleaned = target.replace("https://", "").replace("http://", "")
        cleaned = cleaned.split("/")[0]
        return cleaned
    return target


def scan_one_target(target: str, api_key: str, email: str | None = None):
    target_type = detect_target_type(target)
    network_target = get_network_target(target, target_type)

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


@router.get("/scan/{target:path}")
def scan(
    target: str,
    api_key: str = Query(...),
    email: str | None = Query(default=None)
):
    try:
        targets = [t.strip() for t in target.split(",") if t.strip()]

        if not targets:
            raise HTTPException(status_code=400, detail="No valid targets provided.")

        results = [scan_one_target(t, api_key, email) for t in targets]

        # keep old behavior for single target
        if len(results) == 1:
            return results[0]

        comparison = []
        for item in results:
            scores = item.get("scores", {})
            comparison.append(
                {
                    "target": item.get("target"),
                    "target_type": item.get("target_type"),
                    "exposure": scores.get("exposure", 0),
                    "threat": scores.get("threat", 0),
                    "context": scores.get("context", 0),
                    "risk": scores.get("risk", 0),
                    "malicious": item.get("data", {}).get("vt_malicious", 0),
                    "open_ports": len(item.get("data", {}).get("open_ports", []) or []),
                    "alert_triggered": item.get("alert_triggered", False),
                    "email_status": item.get("email_status", "Not triggered"),
                }
            )

        return {
            "is_multi_target": True,
            "target_count": len(results),
            "results": results,
            "comparison": comparison,
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