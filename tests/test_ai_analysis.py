"""
Day 5 tests mock the Ollama HTTP call — no local model needs to be
running to verify the logic (parsing, clamping, error handling).
"""

import json
import requests
from unittest.mock import patch, MagicMock

from analyzer.ai_analysis import analyze_with_ai, _extract_json


def _fake_parsed_email(body="Hello, please verify your account immediately."):
    return {
        "from": "support@secure-login.com",
        "display_name": "Account Security",
        "subject": "Urgent: verify now",
        "body": body,
    }


@patch("analyzer.ai_analysis.requests.post")
def test_analyze_with_ai_success(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": '{"score": 82, "explanation": "This email uses urgency tactics and impersonates a security team."}'
    }
    mock_post.return_value = mock_response

    result = analyze_with_ai(_fake_parsed_email())
    assert result["ai_score"] == 82
    assert "urgency" in result["explanation"].lower()


@patch("analyzer.ai_analysis.requests.post")
def test_analyze_with_ai_handles_markdown_wrapped_json(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": '```json\n{"score": 45, "explanation": "Somewhat suspicious."}\n```'
    }
    mock_post.return_value = mock_response

    result = analyze_with_ai(_fake_parsed_email())
    assert result["ai_score"] == 45


@patch("analyzer.ai_analysis.requests.post")
def test_analyze_with_ai_clamps_out_of_range_score(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": '{"score": 150, "explanation": "test"}'
    }
    mock_post.return_value = mock_response

    result = analyze_with_ai(_fake_parsed_email())
    assert result["ai_score"] == 100


@patch("analyzer.ai_analysis.requests.post")
def test_analyze_with_ai_connection_error(mock_post):
    mock_post.side_effect = requests.exceptions.ConnectionError()

    result = analyze_with_ai(_fake_parsed_email())
    assert result["ai_score"] == 0
    assert "could not connect" in result["explanation"].lower()


@patch("analyzer.ai_analysis.requests.post")
def test_analyze_with_ai_timeout(mock_post):
    mock_post.side_effect = requests.exceptions.Timeout()

    result = analyze_with_ai(_fake_parsed_email())
    assert result["ai_score"] == 0
    assert "timed out" in result["explanation"].lower()


@patch("analyzer.ai_analysis.requests.post")
def test_analyze_with_ai_unparseable_response(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {"response": "I cannot help with that."}
    mock_post.return_value = mock_response

    result = analyze_with_ai(_fake_parsed_email())
    assert result["ai_score"] == 0
    assert "unparseable" in result["explanation"].lower()


def test_extract_json_plain():
    result = _extract_json('{"score": 10, "explanation": "fine"}')
    assert result["score"] == 10


def test_extract_json_with_surrounding_text():
    result = _extract_json('Sure, here is the analysis:\n{"score": 55, "explanation": "hmm"}\nHope that helps!')
    assert result["score"] == 55


# --- Day 8: Groq provider tests (hosted free-tier path used in production) ---
# AI_PROVIDER and GROQ_API_KEY are monkeypatched per-test rather than via env
# vars, since ai_analysis.py reads them once at import time into module-level
# constants.

def test_analyze_with_groq_success(monkeypatch):
    import analyzer.ai_analysis as ai_mod
    monkeypatch.setattr(ai_mod, "AI_PROVIDER", "groq")
    monkeypatch.setattr(ai_mod, "GROQ_API_KEY", "fake-test-key")

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "choices": [{"message": {"content": '{"score": 88, "explanation": "Urgent tone, spoofed domain."}'}}]
    }
    mock_response.raise_for_status = lambda: None

    with patch("analyzer.ai_analysis.requests.post", return_value=mock_response) as mock_post:
        result = ai_mod.analyze_with_ai(_fake_parsed_email())
        assert result["ai_score"] == 88
        assert result["available"] is True
        assert result["provider"] == "groq"
        # confirm it hit Groq's endpoint with an auth header, not Ollama's
        called_url = mock_post.call_args[0][0]
        called_headers = mock_post.call_args[1]["headers"]
        assert called_url == ai_mod.GROQ_URL
        assert called_headers["Authorization"] == "Bearer fake-test-key"


def test_analyze_with_groq_missing_api_key(monkeypatch):
    import analyzer.ai_analysis as ai_mod
    monkeypatch.setattr(ai_mod, "AI_PROVIDER", "groq")
    monkeypatch.setattr(ai_mod, "GROQ_API_KEY", "")

    result = ai_mod.analyze_with_ai(_fake_parsed_email())
    assert result["available"] is False
    assert result["ai_score"] == 0
    assert "GROQ_API_KEY not set" in result["explanation"]


def test_analyze_with_groq_rate_limited(monkeypatch):
    import analyzer.ai_analysis as ai_mod
    monkeypatch.setattr(ai_mod, "AI_PROVIDER", "groq")
    monkeypatch.setattr(ai_mod, "GROQ_API_KEY", "fake-test-key")

    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_response.raise_for_status = MagicMock(
        side_effect=requests.exceptions.HTTPError(response=mock_response)
    )

    with patch("analyzer.ai_analysis.requests.post", return_value=mock_response):
        result = ai_mod.analyze_with_ai(_fake_parsed_email())
        assert result["available"] is False
        assert "rate limit" in result["explanation"].lower()


def test_analyze_with_groq_invalid_key(monkeypatch):
    import analyzer.ai_analysis as ai_mod
    monkeypatch.setattr(ai_mod, "AI_PROVIDER", "groq")
    monkeypatch.setattr(ai_mod, "GROQ_API_KEY", "wrong-key")

    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.raise_for_status = MagicMock(
        side_effect=requests.exceptions.HTTPError(response=mock_response)
    )

    with patch("analyzer.ai_analysis.requests.post", return_value=mock_response):
        result = ai_mod.analyze_with_ai(_fake_parsed_email())
        assert result["available"] is False
        assert "401" in result["explanation"]


def test_analyze_with_ai_disabled_regardless_of_provider(monkeypatch):
    import analyzer.ai_analysis as ai_mod
    monkeypatch.setattr(ai_mod, "AI_ENABLED", False)
    monkeypatch.setattr(ai_mod, "AI_PROVIDER", "groq")

    result = ai_mod.analyze_with_ai(_fake_parsed_email())
    assert result["available"] is False
    assert result["ai_score"] == 0
