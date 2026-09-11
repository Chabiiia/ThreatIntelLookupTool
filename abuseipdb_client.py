import requests

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

class IPDBError(Exception):
    pass

def lookup_ip(ip: str,api_key :str) -> dict:
    headers = {"key": api_key,"Accept": "application/json"}
    params = {"ipAddress":ip,"maxAgeInDays" :90 }

    response = requests.get(BASE_URL, params=params, headers=headers, timeout=15)

    if response.status_code != 200:
        raise IPDBError(f"AbuseIPDB lookup failed: {response.status_code} - {response.text}")

    data = response.json()["data"]

    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore",0),
        "total_reports": data.get("totalReports",0),
        "country_code": data.get("countryCode","unknown"),
        "isp":data.get("isp","unknown"),
        "is_whitelisted":data.get("isWhitelisted",False),
        "last_reported_at":data.get("lastReportedAt"),
    }