import nmap
import requests
import re
import whois
import ssl
import socket


def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-F")

    result = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                result.append(
                    {
                        "port": port,
                        "state": nm[host][proto][port]["state"],
                    }
                )
    return result


def run_virustotal_scan(target, api_key, target_type):
    headers = {"x-apikey": api_key}

    if target_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
        response = requests.get(url, headers=headers, timeout=30)

    elif target_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        response = requests.get(url, headers=headers, timeout=30)

    elif target_type == "url":
        submit_url = "https://www.virustotal.com/api/v3/urls"
        submit_response = requests.post(
            submit_url,
            headers=headers,
            data={"url": target},
            timeout=30
        )
        submit_response.raise_for_status()

        analysis_id = submit_response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(analysis_url, headers=headers, timeout=30)

    elif target_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{target}"
        response = requests.get(url, headers=headers, timeout=30)

    else:
        return {"malicious": 0, "total": 0}

    response.raise_for_status()

    payload = response.json()
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    return {"malicious": malicious, "total": total}


def detect_target_type(target):
    if re.match(r"^https?://", target):
        return "url"
    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", target):
        return "hash"
    else:
        return "domain"
    



def run_whois_scan(target):
    try:
        data = whois.whois(target)
        return {
            "domain_age": str(data.creation_date),
            "registrar": data.registrar
        }
    except:
        return {}
    


def run_ssl_check(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {"ssl_valid": True}
    except:
        return {"ssl_valid": False}