import requests

BASE_URL="https://www.virustotal.com/api/v3"

class VTError(Exception):
    pass

def _headers(api_key:str) -> dict:
    return {"x-apikey": api_key}

def lookup_ip(ip:str,api_key:str) -> dict:
    url =f"{BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=_headers(api_key), timeout=15)

    if response.status_code == 404:
        return {"found":False}
    if response.status_code != 200:
        raise VTError(f"VirusTotal IP lookup failed: {response.status_code} - {response.text}")

    data = response.json()["data"]["attributes"]
    stats= data.get("last_analysis_stats",{})

    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": data.get("country", "unknown"),
        "as_owner": data.get("as_owner", "unknown"),
    }
def lookup_hash(file_hash:str,api_key:str) -> dict:
    url=f"{BASE_URL}/files/{file_hash}"
    response=requests.get(url,headers=_headers(api_key),timeout=15)

    if response.status_code == 404:
        return {"found":False}
    if response.status_code != 200:
        raise VTError(f"VirusTotal hash lookup failed: {response.status_code} - {response.text}")

    data = response.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats",{})

    return {
        "found":True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "type_description": data.get("type_description","unknown"),
        "meaningful_name":data.get("meaningful_name","unknown")

    }