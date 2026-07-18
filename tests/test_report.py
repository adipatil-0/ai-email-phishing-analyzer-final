import io
import pdfplumber

from analyzer.report import generate_incident_report_pdf


def _sample_record(**overrides):
    record = {
        "id": 1,
        "sender": "attacker@fake-bank.com",
        "subject": "URGENT: Verify your account now",
        "heuristic_score": 85,
        "ai_score": 92,
        "final_score": 87.8,
        "verdict": "MALICIOUS",
        "triggered_indicators": "spoofed_domain,urgency_language,credential_request",
        "analyzed_at": "2026-07-18 10:30:00",
    }
    record.update(overrides)
    return record


def _extract_text(pdf_bytes: io.BytesIO) -> str:
    pdf_bytes.seek(0)
    with pdfplumber.open(pdf_bytes) as pdf:
        return pdf.pages[0].extract_text()


def test_generates_valid_pdf_bytes():
    pdf = generate_incident_report_pdf(_sample_record())
    pdf.seek(0)
    header = pdf.read(4)
    assert header == b"%PDF"


def test_report_contains_key_fields():
    record = _sample_record()
    text = _extract_text(generate_incident_report_pdf(record))
    assert "MALICIOUS" in text
    assert record["sender"] in text
    assert record["subject"] in text
    assert "87.8" in text


def test_report_no_broken_glyphs():
    # Regression test: &#8226; (bullet) and &#9888; (warning sign) previously
    # rendered as (cid:127) / stray characters because those glyphs aren't
    # in the base Helvetica font reportlab uses by default.
    text = _extract_text(generate_incident_report_pdf(_sample_record()))
    assert "(cid:" not in text


def test_degraded_mode_shows_warning():
    # ai_score == 0 and final_score == heuristic_score is the signature of
    # the ai_available=False reweight path in scoring.py (see test_scoring.py).
    record = _sample_record(
        heuristic_score=55, ai_score=0, final_score=55, verdict="SUSPICIOUS",
    )
    text = _extract_text(generate_incident_report_pdf(record))
    assert "WARNING" in text
    assert "did not run" in text
    assert "100%" in text
    assert "N/A" in text


def test_normal_mode_no_degraded_warning():
    record = _sample_record()  # ai_score=92, final_score != heuristic_score
    text = _extract_text(generate_incident_report_pdf(record))
    assert "WARNING" not in text
    assert "60%" in text
    assert "40%" in text


def test_no_indicators_handled_gracefully():
    record = _sample_record(triggered_indicators="", verdict="CLEAN")
    text = _extract_text(generate_incident_report_pdf(record))
    assert "No indicators triggered." in text


def test_missing_optional_fields_do_not_crash():
    # Simulates a record with nulls, e.g. sender/subject failed to parse
    record = _sample_record(sender=None, subject=None, triggered_indicators=None)
    pdf = generate_incident_report_pdf(record)
    pdf.seek(0)
    assert pdf.read(4) == b"%PDF"
