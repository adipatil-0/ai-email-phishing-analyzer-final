"""
Day 5 (local) + Day 8 update (hosted): AI-based email analysis.

Two interchangeable providers, selected via AI_PROVIDER env var:

  - "ollama" (default, for local dev): runs against a local Ollama daemon.
    Free, private, no API key — but needs a persistent process + RAM for
    model weights, which Render's free web tier doesn't have.

  - "groq"   (for deployment): hosted, OpenAI-compatible API, genuinely
    free tier (no credit card), fast (LPU-accelerated). This is what
    render.yaml sets AI_PROVIDER to, so the AI layer stays ON in
    production instead of being disabled.

Both paths return the same shape and share the same prompt + JSON
parsing, so scoring.py and the rest of the app don't care which one ran.

Design principle, same as threat_intel.py: never crash the app if a
provider is unreachable, misconfigured, or the response can't be parsed.
Always return a usable result dict, degrading gracefully to ai_score=0,
available=False with an explanatory message.
"""

import os
import re
import json
import requests

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").lower()  # "ollama" or "groq"

# --- Ollama (local) settings ---
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_TIMEOUT = 30  # local inference on small models is slow-ish on 2-4GB RAM

# --- Groq (hosted, free tier) settings ---
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TIMEOUT = 15  # Groq's LPUs are fast; a slow response usually means trouble

# AI_ENABLED lets you force the whole layer off regardless of provider
# (e.g. to test the degraded 100%-heuristic scoring path deliberately).
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst reviewing an email for phishing indicators.

Analyze the email below and respond with ONLY a JSON object in this exact format, nothing else:
{"score": <integer 0-100>, "explanation": "<2-3 sentence plain-English explanation>"}

Scoring guide:
- 0-20: Clearly legitimate, no red flags
- 21-40: Minor concerns, likely legitimate
- 41-70: Suspicious, multiple concerning patterns
- 71-100: Strong phishing indicators, high confidence malicious

Focus on: urgency/pressure tactics, impersonation of trusted brands, requests for
credentials or sensitive info, mismatched sender identity, generic greetings,
grammar/tone inconsistent with claimed sender.

Respond with ONLY the JSON object, no markdown formatting, no extra text."""


def _build_user_prompt(parsed_email: dict) -> str:
    return (
        f"From: {parsed_email.get('from') or 'unknown'}\n"
        f"Display name: {parsed_email.get('display_name') or 'none'}\n"
        f"Subject: {parsed_email.get('subject') or 'none'}\n\n"
        f"Body:\n{(parsed_email.get('body') or '')[:2000]}"  # cap length
    )


def _extract_json(text: str) -> dict:
    """
    Models sometimes wrap JSON in markdown fences or add stray text
    despite instructions. This pulls out the first valid {...} block
    instead of trusting the raw response.
    """
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in model response")
    return json.loads(match.group(0))


def _score_from_parsed(parsed: dict) -> tuple:
    score = int(parsed.get("score", 0))
    score = max(0, min(score, 100))  # clamp defensively
    explanation = str(parsed.get("explanation", "")).strip() or "No explanation provided by model."
    return score, explanation


def _analyze_with_ollama(prompt: str) -> dict:
    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "system": SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        raw_text = response.json().get("response", "")
        score, explanation = _score_from_parsed(_extract_json(raw_text))
        return {"ai_score": score, "available": True, "explanation": explanation, "provider": "ollama"}

    except requests.exceptions.ConnectionError:
        return {
            "ai_score": 0, "available": False, "provider": "ollama",
            "explanation": (
                f"AI analysis unavailable: could not connect to Ollama at {OLLAMA_HOST}. "
                f"Make sure 'ollama serve' is running."
            ),
        }
    except requests.exceptions.Timeout:
        return {
            "ai_score": 0, "available": False, "provider": "ollama",
            "explanation": "AI analysis timed out — local model may be overloaded or too slow for this VM.",
        }
    except (ValueError, json.JSONDecodeError):
        return {
            "ai_score": 0, "available": False, "provider": "ollama",
            "explanation": "AI analysis returned an unparseable response — model may need a different prompt format.",
        }
    except Exception as e:
        return {"ai_score": 0, "available": False, "provider": "ollama", "explanation": f"AI analysis failed: {str(e)}"}


def _analyze_with_groq(prompt: str) -> dict:
    if not GROQ_API_KEY:
        return {
            "ai_score": 0, "available": False, "provider": "groq",
            "explanation": (
                "AI analysis unavailable: GROQ_API_KEY not set. Get a free key at "
                "https://console.groq.com/keys and add it to your environment."
            ),
        }

    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 300,
            },
            timeout=GROQ_TIMEOUT,
        )
        response.raise_for_status()
        raw_text = response.json()["choices"][0]["message"]["content"]
        score, explanation = _score_from_parsed(_extract_json(raw_text))
        return {"ai_score": score, "available": True, "explanation": explanation, "provider": "groq"}

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        if status == 401:
            msg = "AI analysis failed: Groq rejected the API key (401) — check GROQ_API_KEY."
        elif status == 429:
            msg = "AI analysis unavailable: Groq free-tier rate limit hit (429) — try again shortly."
        else:
            msg = f"AI analysis failed: Groq returned HTTP {status}."
        return {"ai_score": 0, "available": False, "provider": "groq", "explanation": msg}
    except requests.exceptions.ConnectionError:
        return {
            "ai_score": 0, "available": False, "provider": "groq",
            "explanation": "AI analysis unavailable: could not reach api.groq.com (network issue).",
        }
    except requests.exceptions.Timeout:
        return {
            "ai_score": 0, "available": False, "provider": "groq",
            "explanation": "AI analysis timed out — Groq is usually fast, so this may indicate an outage.",
        }
    except (ValueError, KeyError, json.JSONDecodeError):
        return {
            "ai_score": 0, "available": False, "provider": "groq",
            "explanation": "AI analysis returned an unparseable response from Groq.",
        }
    except Exception as e:
        return {"ai_score": 0, "available": False, "provider": "groq", "explanation": f"AI analysis failed: {str(e)}"}


def analyze_with_ai(parsed_email: dict) -> dict:
    """
    Returns {"ai_score": int 0-100, "explanation": str, "available": bool, "provider": str}.
    "available" tells scoring.py whether this layer actually ran, so a
    disabled/unreachable AI layer doesn't get silently blended in as a
    real 0/100 score (which would just drag every verdict toward CLEAN).

    Provider is chosen via AI_PROVIDER ("ollama" local dev / "groq" hosted
    free tier for deployment). Falls back to ai_score=0, available=False
    if AI_ENABLED is off, the chosen provider is unreachable/misconfigured,
    or the response can't be parsed.
    """
    if not AI_ENABLED:
        return {
            "ai_score": 0,
            "available": False,
            "provider": AI_PROVIDER,
            "explanation": "AI analysis layer disabled (AI_ENABLED=false). Verdict is based on heuristics + threat intel only.",
        }

    prompt = _build_user_prompt(parsed_email)

    if AI_PROVIDER == "groq":
        return _analyze_with_groq(prompt)
    return _analyze_with_ollama(prompt)
