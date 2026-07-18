"""
Day 4: Threat intelligence enrichment — VirusTotal URL/IP reputation +
WHOIS domain age lookup.

Design principle: this module must NEVER crash the app if the API key
is missing, the network is down, or the API rate-limits us. Every
function degrades gracefully and returns a result dict with an
'available' flag so callers know whether to trust the data.

Weight allocation for this enrichment layer (separate 0-100 score,
later blended with the offline heuristic score in app.py):
    Malicious URL/IP confirmed by VirusTotal  -> 60
    Domain registered < 30 days ago (WHOIS)    -> 40
"""

import os
import re
import requests
import whois as whois_lib
from datetime import datetime, timezone

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 8  # seconds — never let a slow API hang the analysis

ENRICHMENT_WEIGHTS = {
    "malicious_url": 60,
    "young_domain": 40,
}

YOUNG_DOMAIN_THRESHOLD_DAYS = 30


def _vt_headers():
    return {"x-apikey": VT_API_KEY}


def check_url_reputation(url: str) -> dict:
    """
    Submits/looks up a URL on VirusTotal. Returns:
      {available, malicious_count, total_engines, verdict, error}
    VirusTotal requires the URL identifier to be base64 (no padding) —
    handled internally so callers just pass the raw URL.
    """
    if not VT_API_KEY:
        return {"available": False, "error": "VIRUSTOTAL_API_KEY not configured"}

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=_vt_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            # Not yet analyzed by VT — submit it, then report "unknown" for now
            # (polling for results would need async handling; out of scope for MVP)
            requests.post(
                f"{VT_BASE_URL}/urls",
                headers=_vt_headers(),
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            return {"available": True, "malicious_count": 0, "total_engines": 0,
                     "verdict": "unknown", "error": None}

        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        verdict = "malicious" if malicious > 0 else "clean"

        return {
            "available": True,
            "malicious_count": malicious,
            "total_engines": total,
            "verdict": verdict,
            "error": None,
        }

    except requests.exceptions.RequestException as e:
        return {"available": False, "error": str(e)}


def check_domain_age(domain: str) -> dict:
    """
    WHOIS lookup for domain registration date. Returns:
      {available, age_days, created_date, error}
    """
    if not domain:
        return {"available": False, "error": "no domain provided"}

    try:
        w = whois_lib.whois(domain)
        created = w.creation_date

        if isinstance(created, list):
            created = created[0]

        if not created:
            return {"available": False, "error": "no creation date returned"}

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - created).days

        return {
            "available": True,
            "age_days": age_days,
            "created_date": created.isoformat(),
            "error": None,
        }

    except Exception as e:
        return {"available": False, "error": str(e)}


def enrich_with_threat_intel(parsed_email: dict) -> dict:
    """
    Runs VirusTotal on all URLs and WHOIS on the sender domain, combines
    into a 0-100 enrichment score with human-readable indicators.

    If NO checks were available (no API key, all network calls failed),
    returns {"ran": False, ...} so app.py can fall back to pure heuristic
    scoring instead of pretending enrichment happened.
    """
    urls = parsed_email.get("urls") or []
    domain = parsed_email.get("sender_domain") or ""

    score = 0
    indicators = []
    any_check_ran = False

    # Check up to 5 URLs to avoid excessive API calls / rate limits
    for url in urls[:5]:
        result = check_url_reputation(url)
        if result["available"]:
            any_check_ran = True
            if result["verdict"] == "malicious":
                score += ENRICHMENT_WEIGHTS["malicious_url"]
                indicators.append(
                    f"VirusTotal flagged URL as malicious ({result['malicious_count']}/{result['total_engines']} engines): {url}"
                )
                break  # one confirmed malicious URL is enough signal

    if domain:
        domain_result = check_domain_age(domain)
        if domain_result["available"]:
            any_check_ran = True
            if domain_result["age_days"] < YOUNG_DOMAIN_THRESHOLD_DAYS:
                score += ENRICHMENT_WEIGHTS["young_domain"]
                indicators.append(
                    f"Sending domain '{domain}' registered only {domain_result['age_days']} days ago"
                )

    return {
        "ran": any_check_ran,
        "score": min(score, 100),
        "indicators": indicators,
    }
