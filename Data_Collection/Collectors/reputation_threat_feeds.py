# reputation_threat_feeds.py
# Reputation & Threat-Feeds retrieval for StealthPhisher2025 pipeline

import requests
import hashlib
import time

# -------------- Google Safe Browsing ----------------
def get_google_safebrowsing(api_key: str, url: str) -> dict:
    """
    Checks a URL against Google Safe Browsing v4 API.
    Returns threat verdicts (malware, phishing, unwanted software).
    Requires: GOOGLE_API_KEY env var or passed in.
    """
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body = {
        "client": {
            "clientId": "StealthPhisher2025",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": api_key}
    try:
        resp = requests.post(endpoint, params=params, json=body, timeout=5)
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    matches = data.get("matches", [])
    return {
        "SafeBrowsingMatches": matches,
        "IsListedByGSB": 1 if matches else 0
    }

# -------------- VirusTotal URL/Domain Scan ----------------
def get_virustotal_url(api_key: str, url: str) -> dict:
    """
    Retrieves VirusTotal URL scan report:
    - number of engines flagging as malicious
    - raw scans dict
    Requires: VT API key.
    """
    # VT expects a URL ID: base64url without padding
    url_id = hashlib.sha256(url.encode()).hexdigest()
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=5)
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "VT_Harmless": stats.get("harmless", 0),
        "VT_Malicious": stats.get("malicious", 0),
        "VT_Suspicious": stats.get("suspicious", 0),
        "VT_Undetected": stats.get("undetected", 0),
        "VT_AnalysisDate": data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
        "VT_Scans": data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    }

# -------------- PhishTank Check ----------------
def get_phishtank_status(url: str, app_key: str = None) -> dict:
    """
    Checks a URL against PhishTank database.
    Returns whether URL is verified phishing.
    Optional: include your application key.
    """
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    data = {"url": url, "format": "json"}
    if app_key:
        data["app_key"] = app_key

    try:
        resp = requests.post(endpoint, data=data, timeout=5)
        result = resp.json().get("results", {})
    except Exception as e:
        return {"error": str(e)}

    return {
        "PhishTankValid": result.get("valid", False),
        "PhishTankInDatabase": result.get("in_database", False),
        "PhishTankVerified": result.get("verified", False)
    }

# -------------- Web of Trust (WOT) ----------------
def get_wot_reputation(api_key: str, domain: str) -> dict:
    """
    Retrieves community reputation scores from Web of Trust API.
    Returns domain ratings for trustworthiness, child safety.
    """
    endpoint = f"http://api.mywot.com/0.4/public_link_json2"
    params = {"hosts": domain + "/", "key": api_key}
    try:
        resp = requests.get(endpoint, params=params, timeout=5)
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    scores = data.get(domain + "/", [None, None, None])
    # scores = [trust, child_safety]
    return {
        "WOT_Trust": scores[0],
        "WOT_ChildSafety": scores[1]
    }


if __name__ == "__main__":
    # Example usage
    test_url = "http://example.com/malicious"
    gsb = get_google_safebrowsing(api_key="YOUR_GOOGLE_KEY", url=test_url)
    print("Safe Browsing:", gsb)

    vt  = get_virustotal_url(api_key="YOUR_VT_KEY", url=test_url)
    print("VirusTotal:", vt)

    pt  = get_phishtank_status(test_url)
    print("PhishTank:", pt)

    wot = get_wot_reputation(api_key="YOUR_WOT_KEY", domain="example.com")
    print("WOT:", wot)
