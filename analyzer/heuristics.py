"""
Day 3: Offline, rule-based phishing heuristics.

No API calls here on purpose — this engine must work with zero
external dependencies, zero cost, zero rate limits. It operates
only on what parser.py already extracted.

Weight allocation (Day 3 scope, sums to 100):
    SPF/DKIM/DMARC failure        -> 35
    Urgency / threat language     -> 20
    Display name vs domain mismatch -> 15
    IP-literal URL present        -> 15
    Risky attachment extension    -> 15

Day 4 will fold in domain age (WHOIS) and VirusTotal URL/IP verdicts
as additional signals — at that point these weights get rebalanced
to make room. For now this is the complete offline picture.
"""

import re

WEIGHTS = {
    "auth_failure": 35,
    "urgency_language": 20,
    "display_name_mismatch": 15,
    "ip_literal_url": 15,
    "risky_attachment": 15,
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify your account", "account suspended",
    "act now", "immediate action", "confirm your identity", "click here",
    "limited time", "your account will be", "unusual activity",
    "suspended", "expire", "restricted", "unauthorized access",
    "final notice", "failure to", "24 hours", "verify now",
]

RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar",
    ".ps1", ".msi", ".com", ".pif",
}

MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def _check_auth_failure(parsed_email: dict) -> tuple:
    """Returns (triggered: bool, reason: str or None)."""
    if not parsed_email.get("has_auth_data"):
        return False, None  # can't judge what we don't have (pasted text)

    failures = []
    for mechanism in ("spf", "dkim", "dmarc"):
        value = parsed_email.get(mechanism)
        if value == "fail":
            failures.append(mechanism.upper())

    if failures:
        return True, f"Authentication failed: {', '.join(failures)}"
    return False, None


def _check_urgency_language(parsed_email: dict) -> tuple:
    body = (parsed_email.get("body") or "").lower()
    subject = (parsed_email.get("subject") or "").lower()
    combined = f"{subject} {body}"

    hits = [kw for kw in URGENCY_KEYWORDS if kw in combined]
    if hits:
        return True, f"Urgency/threat language detected: {', '.join(hits[:3])}"
    return False, None


def _check_display_name_mismatch(parsed_email: dict) -> tuple:
    """
    Flags cases like: Display name = 'PayPal Support' but sender domain
    is something unrelated like 'secure-login.com'. Rough heuristic:
    if the display name contains a well-known brand-like word that
    doesn't appear anywhere in the actual sending domain, flag it.
    """
    display_name = (parsed_email.get("display_name") or "").lower()
    domain = (parsed_email.get("sender_domain") or "").lower()

    if not display_name or not domain:
        return False, None

    # strip common corporate suffixes to get the "brand" word(s)
    cleaned = re.sub(r"\b(team|support|security|service|noreply|no-reply|admin)\b", "", display_name)
    words = [w for w in re.findall(r"[a-z]+", cleaned) if len(w) > 3]

    if not words:
        return False, None

    domain_root = domain.split(".")[0]
    mismatch = all(word not in domain_root and domain_root not in word for word in words)

    if mismatch:
        return True, f"Display name '{parsed_email.get('display_name')}' does not match sending domain '{domain}'"
    return False, None


def _check_ip_literal_url(parsed_email: dict) -> tuple:
    ip_urls = parsed_email.get("ip_urls") or []
    if ip_urls:
        return True, f"Email links directly to raw IP address(es): {', '.join(ip_urls[:2])}"
    return False, None


def _check_risky_attachment(parsed_email: dict) -> tuple:
    attachments = parsed_email.get("attachments") or []
    flagged = []
    for filename in attachments:
        if not filename:
            continue
        lower = filename.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in RISKY_ATTACHMENT_EXTENSIONS:
            flagged.append(f"{filename} (executable)")
        elif ext in MACRO_ENABLED_EXTENSIONS:
            flagged.append(f"{filename} (macro-enabled)")

    if flagged:
        return True, f"Risky attachment(s): {', '.join(flagged)}"
    return False, None


CHECKS = [
    ("auth_failure", _check_auth_failure),
    ("urgency_language", _check_urgency_language),
    ("display_name_mismatch", _check_display_name_mismatch),
    ("ip_literal_url", _check_ip_literal_url),
    ("risky_attachment", _check_risky_attachment),
]


def score_heuristics(parsed_email: dict) -> dict:
    """
    Runs all offline checks against the parsed email and returns a
    weighted score (0-100) plus the list of human-readable indicators
    that triggered, for display in the UI and incident reports.
    """
    total_score = 0
    triggered_indicators = []

    for weight_key, check_fn in CHECKS:
        triggered, reason = check_fn(parsed_email)
        if triggered:
            total_score += WEIGHTS[weight_key]
            triggered_indicators.append(reason)

    total_score = min(total_score, 100)

    return {
        "score": total_score,
        "triggered_indicators": triggered_indicators,
    }
