def calculate_scores(data):
    exposure = min(len(data['open_ports']) * 10, 100)

    threat = (data['vt_malicious'] / data['vt_total'] * 100
              if data['vt_total'] > 0 else 0)

    context = 50
    if data['ssl']:
        context += 20
    if data['security_headers'] > 3:
        context += 30

    context = min(context, 100)

    risk = (exposure + threat + context) / 3

    return {
        "exposure": exposure,
        "threat": threat,
        "context": context,
        "risk": risk
    }