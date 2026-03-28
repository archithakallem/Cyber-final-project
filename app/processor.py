def process_data(nmap_data, vt_data):
    structured = {
        "open_ports": nmap_data,
        "vt_malicious": vt_data["malicious"],
        "vt_total": vt_data["total"],
        "ssl": True,
        "security_headers": 2,
    }
    return structured