"""
Day 4 tests use mocked requests/whois calls — no real network hits, no
API key required, no rate limit risk. This is standard practice: unit
tests should never depend on live external services being up.
"""

from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from analyzer.threat_intel import (
    check_url_reputation,
    check_domain_age,
    enrich_with_threat_intel,
)


def test_check_url_reputation_no_api_key(monkeypatch):
    monkeypatch.setattr("analyzer.threat_intel.VT_API_KEY", "")
    result = check_url_reputation("http://example.com")
    assert result["available"] is False
    assert "not configured" in result["error"]


@patch("analyzer.threat_intel.requests.get")
def test_check_url_reputation_malicious(mock_get, monkeypatch):
    monkeypatch.setattr("analyzer.threat_intel.VT_API_KEY", "fake_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {
            "malicious": 12, "suspicious": 3, "harmless": 76, "undetected": 0
        }}}
    }
    mock_get.return_value = mock_response

    result = check_url_reputation("http://malicious-example.com")
    assert result["available"] is True
    assert result["verdict"] == "malicious"
    assert result["malicious_count"] == 12
    assert result["total_engines"] == 91


@patch("analyzer.threat_intel.requests.get")
def test_check_url_reputation_clean(mock_get, monkeypatch):
    monkeypatch.setattr("analyzer.threat_intel.VT_API_KEY", "fake_key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 91, "undetected": 0
        }}}
    }
    mock_get.return_value = mock_response

    result = check_url_reputation("http://google.com")
    assert result["verdict"] == "clean"
    assert result["malicious_count"] == 0


@patch("analyzer.threat_intel.whois_lib.whois")
def test_check_domain_age_young_domain(mock_whois):
    mock_result = MagicMock()
    mock_result.creation_date = datetime.now(timezone.utc) - timedelta(days=5)
    mock_whois.return_value = mock_result

    result = check_domain_age("brand-new-scam.xyz")
    assert result["available"] is True
    assert result["age_days"] == 5


@patch("analyzer.threat_intel.whois_lib.whois")
def test_check_domain_age_old_domain(mock_whois):
    mock_result = MagicMock()
    mock_result.creation_date = datetime.now(timezone.utc) - timedelta(days=3650)
    mock_whois.return_value = mock_result

    result = check_domain_age("github.com")
    assert result["available"] is True
    assert result["age_days"] >= 3650


@patch("analyzer.threat_intel.whois_lib.whois")
def test_check_domain_age_handles_missing_creation_date(mock_whois):
    mock_result = MagicMock()
    mock_result.creation_date = None
    mock_whois.return_value = mock_result

    result = check_domain_age("weird-domain.test")
    assert result["available"] is False


@patch("analyzer.threat_intel.check_domain_age")
@patch("analyzer.threat_intel.check_url_reputation")
def test_enrich_combines_malicious_url_and_young_domain(mock_url_check, mock_domain_check):
    mock_url_check.return_value = {
        "available": True, "verdict": "malicious",
        "malicious_count": 15, "total_engines": 91, "error": None,
    }
    mock_domain_check.return_value = {
        "available": True, "age_days": 3, "created_date": "2026-07-09", "error": None,
    }

    parsed_email = {
        "urls": ["http://fake-bank-login.com/verify"],
        "sender_domain": "fake-bank-login.com",
    }

    result = enrich_with_threat_intel(parsed_email)
    assert result["ran"] is True
    assert result["score"] == 100  # 60 (malicious url) + 40 (young domain)
    assert len(result["indicators"]) == 2


@patch("analyzer.threat_intel.check_domain_age")
@patch("analyzer.threat_intel.check_url_reputation")
def test_enrich_returns_ran_false_when_nothing_available(mock_url_check, mock_domain_check):
    mock_url_check.return_value = {"available": False, "error": "no key"}
    mock_domain_check.return_value = {"available": False, "error": "lookup failed"}

    parsed_email = {"urls": ["http://example.com"], "sender_domain": "example.com"}
    result = enrich_with_threat_intel(parsed_email)

    assert result["ran"] is False
    assert result["score"] == 0
    assert result["indicators"] == []


def test_enrich_handles_no_urls_or_domain():
    result = enrich_with_threat_intel({"urls": [], "sender_domain": ""})
    assert result["ran"] is False
    assert result["score"] == 0
