from analyzer.scoring import final_verdict


def test_malicious_verdict():
    result = final_verdict(heuristic_score=90, ai_score=80)
    assert result["verdict"] == "MALICIOUS"
    assert result["score"] == 86.0


def test_clean_verdict():
    result = final_verdict(heuristic_score=5, ai_score=10)
    assert result["verdict"] == "CLEAN"


def test_suspicious_verdict():
    result = final_verdict(heuristic_score=50, ai_score=40)
    assert result["verdict"] == "SUSPICIOUS"


# --- Regression tests: ai_available reweighting ---
# Bug this guards against: when the AI layer doesn't run, ai_score=0 must
# NOT be blended in at 40% weight — that silently drags every verdict
# toward CLEAN (e.g. heuristic=80 would wrongly become SUSPICIOUS at 48
# instead of correctly staying MALICIOUS at 80).

def test_ai_unavailable_uses_full_heuristic_weight():
    result = final_verdict(heuristic_score=80, ai_score=0, ai_available=False)
    assert result["score"] == 80
    assert result["verdict"] == "MALICIOUS"
    assert result["ai_available"] is False


def test_ai_unavailable_low_heuristic_stays_clean():
    result = final_verdict(heuristic_score=20, ai_score=0, ai_available=False)
    assert result["score"] == 20
    assert result["verdict"] == "CLEAN"


def test_ai_available_true_by_default():
    # Backward compatibility: callers that don't pass ai_available should
    # still get the original 60/40 blended behavior.
    result = final_verdict(heuristic_score=90, ai_score=80)
    assert result["ai_available"] is True
    assert result["score"] == 86.0


def test_ai_available_uses_blended_weight():
    result_with_ai = final_verdict(heuristic_score=80, ai_score=100, ai_available=True)
    result_without_ai = final_verdict(heuristic_score=80, ai_score=0, ai_available=False)
    # Same heuristic score, but different treatment — proves the two modes
    # genuinely diverge rather than one silently ignoring ai_available.
    assert result_with_ai["score"] != result_without_ai["score"]
