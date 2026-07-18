import os
from analyzer.parser import parse_eml
from analyzer.heuristics import score_heuristics

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "sample_emails")


def _load(filename):
    with open(os.path.join(SAMPLES_DIR, filename), "rb") as f:
        return f.read()


def test_clean_email_scores_low():
    parsed = parse_eml(_load("clean_github_notification.eml"))
    result = score_heuristics(parsed)
    assert result["score"] == 0
    assert result["triggered_indicators"] == []


def test_phishing_email_scores_high():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    result = score_heuristics(parsed)
    # auth_failure(35) + urgency(20) + ip_literal_url(15) = 70 at minimum
    assert result["score"] >= 70
    assert len(result["triggered_indicators"]) >= 3


def test_phishing_email_flags_auth_failure():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    result = score_heuristics(parsed)
    assert any("Authentication failed" in i for i in result["triggered_indicators"])


def test_phishing_email_flags_urgency():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    result = score_heuristics(parsed)
    assert any("Urgency" in i for i in result["triggered_indicators"])


def test_phishing_email_flags_ip_url():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    result = score_heuristics(parsed)
    assert any("raw IP" in i for i in result["triggered_indicators"])


def test_pasted_text_skips_auth_check():
    # has_auth_data=False means auth_failure check must not fire
    parsed = {
        "has_auth_data": False,
        "spf": None, "dkim": None, "dmarc": None,
        "body": "hello, just a normal message",
        "subject": "hi",
        "display_name": "", "sender_domain": "",
        "ip_urls": [], "attachments": [],
    }
    result = score_heuristics(parsed)
    assert result["score"] == 0


def test_risky_attachment_detected():
    parsed = {
        "has_auth_data": False,
        "spf": None, "dkim": None, "dmarc": None,
        "body": "see attached invoice",
        "subject": "Invoice",
        "display_name": "", "sender_domain": "",
        "ip_urls": [], "attachments": ["invoice.exe"],
    }
    result = score_heuristics(parsed)
    assert result["score"] == 15
    assert "executable" in result["triggered_indicators"][0]


def test_macro_attachment_detected():
    parsed = {
        "has_auth_data": False,
        "spf": None, "dkim": None, "dmarc": None,
        "body": "open the enclosed form",
        "subject": "Form",
        "display_name": "", "sender_domain": "",
        "ip_urls": [], "attachments": ["form.docm"],
    }
    result = score_heuristics(parsed)
    assert result["score"] == 15
    assert "macro-enabled" in result["triggered_indicators"][0]


def test_display_name_mismatch_detected():
    parsed = {
        "has_auth_data": False,
        "spf": None, "dkim": None, "dmarc": None,
        "body": "please verify your payment details",
        "subject": "Payment",
        "display_name": "PayPal Support", "sender_domain": "randommailer123.ru",
        "ip_urls": [], "attachments": [],
    }
    result = score_heuristics(parsed)
    assert any("does not match" in i for i in result["triggered_indicators"])


def test_score_never_exceeds_100():
    parsed = {
        "has_auth_data": True,
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "body": "urgent verify your account immediately act now",
        "subject": "urgent account suspended",
        "display_name": "Bank Security", "sender_domain": "totallyfake.xyz",
        "ip_urls": ["http://1.2.3.4/login"],
        "attachments": ["malware.exe"],
    }
    result = score_heuristics(parsed)
    assert result["score"] <= 100
