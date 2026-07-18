import os
from analyzer.parser import parse_eml, parse_pasted_text

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "sample_emails")


def _load(filename):
    with open(os.path.join(SAMPLES_DIR, filename), "rb") as f:
        return f.read()


def test_clean_email_spf_dkim_pass():
    parsed = parse_eml(_load("clean_github_notification.eml"))
    assert parsed["spf"] == "pass"
    assert parsed["dkim"] == "pass"
    assert parsed["dmarc"] == "pass"
    assert parsed["sender_domain"] == "github.com"
    assert parsed["has_auth_data"] is True


def test_phishing_email_spf_dkim_fail():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    assert parsed["spf"] == "fail"
    assert parsed["dkim"] == "fail"
    assert parsed["dmarc"] == "fail"
    assert parsed["sender_domain"] == "secure-login.com"


def test_phishing_email_extracts_urls():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    assert "http://secure-login-verification.com/login" in parsed["urls"]
    assert any("bit.ly" in u for u in parsed["urls"])
    assert len(parsed["ip_urls"]) == 1
    assert "185.220.101.35" in parsed["ip_urls"][0]


def test_phishing_email_subject_and_sender():
    parsed = parse_eml(_load("phishing_fake_login.eml"))
    assert "URGENT" in parsed["subject"]
    assert parsed["from"] == "support@secure-login.com"


def test_pasted_text_has_no_auth_data():
    text = "From: fake@scam.com\nSubject: Test\nClick http://bad.example.com now"
    parsed = parse_pasted_text(text)
    assert parsed["has_auth_data"] is False
    assert parsed["spf"] is None
    assert parsed["from"] == "fake@scam.com"
    assert "http://bad.example.com" in parsed["urls"]


def test_pasted_text_handles_missing_headers_gracefully():
    text = "just some random text with no headers at all"
    parsed = parse_pasted_text(text)
    assert parsed["from"] is None
    assert parsed["subject"] is None
    assert parsed["urls"] == []
