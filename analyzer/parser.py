"""
Day 2: Email parsing.

Two entry points:
  - parse_eml(file_bytes)      -> full parse, includes SPF/DKIM/DMARC auth headers
  - parse_pasted_text(text)    -> best-effort regex parse, NO auth headers available

Both return the same dict shape so downstream code (heuristics, AI, scoring)
doesn't need to care which path was used.
"""

import email
import re
from email import policy
from email.utils import parseaddr

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+")
IP_URL_REGEX = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def _extract_urls(text: str) -> list:
    if not text:
        return []
    seen = []
    for match in URL_REGEX.findall(text):
        cleaned = match.rstrip(".,;:!?")
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


def _extract_domain(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.split("@")[-1].strip().lower()


def _parse_auth_results(auth_header: str) -> dict:
    """
    Parses a standard 'Authentication-Results' header into
    {'spf': 'pass'|'fail'|'neutral'|None, 'dkim': ..., 'dmarc': ...}
    """
    result = {"spf": None, "dkim": None, "dmarc": None}
    if not auth_header:
        return result

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            result[mechanism] = match.group(1).lower()
    return result


def parse_eml(file_bytes: bytes) -> dict:
    """
    Parses a raw .eml file. This is the authoritative path — gives us
    real SPF/DKIM/DMARC verdicts which pasted text can never provide.
    """
    msg = email.message_from_bytes(file_bytes, policy=policy.default)

    from_header = msg.get("From", "")
    display_name, from_address = parseaddr(from_header)
    sender_domain = _extract_domain(from_address)

    subject = msg.get("Subject", "")

    body = ""
    if msg.get_body(preferencelist=("plain",)):
        body = msg.get_body(preferencelist=("plain",)).get_content()
    elif msg.get_body(preferencelist=("html",)):
        html = msg.get_body(preferencelist=("html",)).get_content()
        body = re.sub(r"<[^>]+>", " ", html)

    auth_header = msg.get("Authentication-Results", "")
    auth = _parse_auth_results(auth_header)

    if auth["spf"] is None:
        received_spf = msg.get("Received-SPF", "")
        spf_match = re.match(r"(\w+)", received_spf)
        if spf_match:
            auth["spf"] = spf_match.group(1).lower()

    dkim_signature_present = msg.get("DKIM-Signature") is not None

    urls = _extract_urls(body)
    ip_urls = [u for u in urls if IP_URL_REGEX.match(u)]

    attachments = [
        part.get_filename()
        for part in msg.iter_attachments()
        if part.get_filename()
    ]

    return {
        "source": "eml",
        "display_name": display_name,
        "from": from_address,
        "sender_domain": sender_domain,
        "subject": subject,
        "body": body.strip(),
        "urls": urls,
        "ip_urls": ip_urls,
        "attachments": attachments,
        "spf": auth["spf"],
        "dkim": auth["dkim"] if auth["dkim"] else ("pass" if dkim_signature_present else None),
        "dmarc": auth["dmarc"],
        "has_auth_data": True,
    }


def parse_pasted_text(text: str) -> dict:
    """
    Best-effort parse for raw pasted text (no headers available).
    Auth results are always None here — flagged via has_auth_data=False
    so heuristics.py knows to skip SPF/DKIM/DMARC scoring for this input.
    """
    from_match = re.search(r"^From:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    subject_match = re.search(r"^Subject:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)

    from_raw = from_match.group(1).strip() if from_match else ""
    display_name, from_address = parseaddr(from_raw)
    sender_domain = _extract_domain(from_address)

    urls = _extract_urls(text)
    ip_urls = [u for u in urls if IP_URL_REGEX.match(u)]

    return {
        "source": "pasted_text",
        "display_name": display_name,
        "from": from_address or from_raw or None,
        "sender_domain": sender_domain,
        "subject": subject_match.group(1).strip() if subject_match else None,
        "body": text.strip(),
        "urls": urls,
        "ip_urls": ip_urls,
        "attachments": [],
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "has_auth_data": False,
    }
