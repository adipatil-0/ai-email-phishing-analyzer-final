import os
from flask import Flask, render_template, request, send_file, abort
from dotenv import load_dotenv

from analyzer.parser import parse_pasted_text, parse_eml
from analyzer.heuristics import score_heuristics
from analyzer.threat_intel import enrich_with_threat_intel
from analyzer.ai_analysis import analyze_with_ai
from analyzer.scoring import final_verdict
from analyzer.report import generate_incident_report_pdf
from database import init_db, save_analysis, get_history, get_stats, get_by_id

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-key-change-me")

init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        # Day 2 will branch this: .eml upload vs pasted text
        email_text = request.form.get("email_text", "")
        uploaded_file = request.files.get("eml_file")

        if uploaded_file and uploaded_file.filename:
            parsed = parse_eml(uploaded_file.read())
        else:
            parsed = parse_pasted_text(email_text)

        heuristic_result = score_heuristics(parsed)

        # Day 4: blend offline heuristics with live threat intel (VirusTotal + WHOIS)
        # Graceful degradation: if no API key or network unavailable, enrichment.ran
        # is False and we fall back to the pure offline heuristic score.
        enrichment = enrich_with_threat_intel(parsed)
        if enrichment["ran"]:
            combined_heuristic_score = round(
                (0.7 * heuristic_result["score"]) + (0.3 * enrichment["score"]), 2
            )
            all_indicators = heuristic_result["triggered_indicators"] + enrichment["indicators"]
        else:
            combined_heuristic_score = heuristic_result["score"]
            all_indicators = heuristic_result["triggered_indicators"]

        ai_result = analyze_with_ai(parsed)

        verdict = final_verdict(
            combined_heuristic_score,
            ai_result["ai_score"],
            ai_available=ai_result.get("available", True),
        )

        record = {
            "sender": parsed.get("from"),
            "subject": parsed.get("subject"),
            "heuristic_score": combined_heuristic_score,
            "ai_score": ai_result["ai_score"],
            "final_score": verdict["score"],
            "verdict": verdict["verdict"],
            "triggered_indicators": all_indicators,
        }
        record_id = save_analysis(record)

        result = {
            **verdict,
            "id": record_id,
            "explanation": ai_result["explanation"],
            "triggered_indicators": all_indicators,
        }

    return render_template("index.html", result=result)


@app.route("/history")
def history():
    # Day 6: filter by verdict, search sender/subject, stats bar
    verdict_filter = request.args.get("verdict") or None
    search_query = request.args.get("q") or None

    records = get_history(verdict=verdict_filter, search=search_query)
    stats = get_stats()

    return render_template(
        "history.html",
        records=records,
        stats=stats,
        verdict_filter=verdict_filter,
        search_query=search_query,
    )


@app.route("/report/<int:record_id>")
def download_report(record_id):
    # Day 7: incident report PDF export
    record = get_by_id(record_id)
    if record is None:
        abort(404, description=f"No analysis record found with id {record_id}")

    pdf_buffer = generate_incident_report_pdf(record)
    filename = f"phishing-report-{record_id}.pdf"

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


if __name__ == "__main__":
    # debug=True enables Flask's interactive debugger, which can leak stack
    # traces / source paths — and in the worst case allows remote code
    # execution if someone finds the debugger console. Never let this be
    # True outside local development. Render uses `gunicorn app:app`
    # (see render.yaml), which never executes this block at all, but this
    # guard protects against ever running `python3 app.py` on a public host.
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true" and not os.getenv("RENDER")
    app.run(debug=debug_mode)
