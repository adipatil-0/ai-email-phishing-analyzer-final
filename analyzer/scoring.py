"""
Combines heuristic score (60% weight) + AI score (40% weight) into final verdict.

Revised: the AI layer is optional at runtime (e.g. disabled on Render since
Ollama is local-only — see analyzer/ai_analysis.py). If it didn't run, we
must NOT blend in a fake ai_score=0 at 40% weight, because that silently
drags every verdict toward CLEAN regardless of how bad the email actually
is. When ai_available=False, heuristic_score carries 100% of the verdict
and the response is flagged so the UI/report can disclose the reduced
confidence.
"""

HEURISTIC_WEIGHT = 0.6
AI_WEIGHT = 0.4


def final_verdict(heuristic_score: float, ai_score: float, ai_available: bool = True) -> dict:
    if ai_available:
        combined = round((HEURISTIC_WEIGHT * heuristic_score) + (AI_WEIGHT * ai_score), 2)
    else:
        combined = round(heuristic_score, 2)

    if combined >= 70:
        verdict = "MALICIOUS"
    elif combined >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "score": combined,
        "verdict": verdict,
        "heuristic_score": heuristic_score,
        "ai_score": ai_score,
        "ai_available": ai_available,
    }
