"""
Day 7: SOC-style incident report PDF export.

Takes a single analyzed_emails record (from database.get_by_id) and renders
it as a downloadable PDF — sender/subject, score breakdown, triggered
indicators, verdict, timestamp. Built with reportlab's Platypus layer
(SimpleDocTemplate + Paragraph/Table) rather than raw canvas drawing,
since this is a structured multi-section document, not free-form text.

Design note: this must handle degraded-mode records gracefully (AI layer
disabled/unavailable — see analyzer/ai_analysis.py + scoring.py). The
report explicitly discloses when a verdict was heuristic-only, the same
way the live UI does, rather than silently omitting the AI section.
"""

import io
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

# Verdict -> color, matching the app's UI palette (red/orange/green)
VERDICT_COLORS = {
    "MALICIOUS": colors.HexColor("#dc2626"),
    "SUSPICIOUS": colors.HexColor("#d97706"),
    "CLEAN": colors.HexColor("#16a34a"),
}


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=20, leading=24, spaceAfter=4,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", fontSize=13, leading=16, spaceBefore=16, spaceAfter=6,
        fontName="Helvetica-Bold", textColor=colors.HexColor("#c2410c"),
    ))
    styles.add(ParagraphStyle(
        name="MetaText", fontSize=9, leading=12, textColor=colors.HexColor("#6b7280"),
    ))
    styles.add(ParagraphStyle(
        name="BodyTextTight", fontSize=10.5, leading=15,
    ))
    return styles


def generate_incident_report_pdf(record: dict) -> io.BytesIO:
    """
    record: a dict as returned by database.get_by_id() — keys are the
    analyzed_emails columns (id, sender, subject, heuristic_score,
    ai_score, final_score, verdict, triggered_indicators, analyzed_at).

    Returns an in-memory BytesIO containing the PDF, ready to send with
    Flask's send_file(). Caller is responsible for seeking to 0 if needed
    (this function already does that).
    """
    styles = _build_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )

    verdict = record.get("verdict", "UNKNOWN")
    verdict_color = VERDICT_COLORS.get(verdict, colors.grey)

    story = []

    # --- Header ---
    story.append(Paragraph("Email Phishing Analysis — Incident Report", styles["ReportTitle"]))
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(
        f"Report ID: {record.get('id', '-')} &nbsp;|&nbsp; Generated: {generated_at}",
        styles["MetaText"],
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb"), thickness=1))
    story.append(Spacer(1, 12))

    # --- Verdict banner ---
    verdict_table = Table(
        [[Paragraph(f"<b>VERDICT: {verdict}</b>", ParagraphStyle(
            name="VerdictText", fontSize=14, textColor=colors.white, fontName="Helvetica-Bold",
        ))]],
        colWidths=[6.5 * inch],
    )
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 16))

    # --- Email details ---
    story.append(Paragraph("Email Details", styles["SectionHeader"]))
    details_data = [
        ["Sender", record.get("sender") or "-"],
        ["Subject", record.get("subject") or "-"],
        ["Analyzed at", record.get("analyzed_at") or "-"],
    ]
    details_table = Table(details_data, colWidths=[1.3 * inch, 5.2 * inch])
    details_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    story.append(details_table)
    story.append(Spacer(1, 16))

    # --- Score breakdown ---
    story.append(Paragraph("Score Breakdown", styles["SectionHeader"]))

    ai_score = record.get("ai_score", 0)
    heuristic_score = record.get("heuristic_score", 0)
    final_score = record.get("final_score", 0)

    # We don't currently persist an ai_available flag in the DB (Day 6
    # schema doesn't have that column), so we infer degraded mode the same
    # way a human reviewer would: ai_score == 0 AND final_score ==
    # heuristic_score is the signature of the ai_available=False reweight
    # path in scoring.py. This is a heuristic inference for reporting
    # purposes only, not used anywhere in the actual scoring logic.
    likely_degraded = (ai_score == 0 and final_score == heuristic_score)

    score_data = [
        ["Component", "Score", "Weight"],
        ["Heuristic + Threat Intel", f"{heuristic_score}", "100%" if likely_degraded else "60%"],
        ["AI Analysis", f"{ai_score}", "N/A (did not run)" if likely_degraded else "40%"],
        ["Final Score", f"{final_score}", "—"],
    ]
    score_table = Table(score_data, colWidths=[3.0 * inch, 1.5 * inch, 2.0 * inch])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fff7ed")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ]))
    story.append(score_table)

    if likely_degraded:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "WARNING: This verdict is based on heuristics and threat intel only. "
            "The AI analysis layer did not run for this email (disabled, "
            "unreachable, or rate-limited at analysis time) — see the app's "
            "README for the AI_PROVIDER / AI_ENABLED configuration.",
            ParagraphStyle(
                name="DegradedNotice", parent=styles["BodyTextTight"],
                textColor=colors.HexColor("#92400e"), fontSize=9.5,
                backColor=colors.HexColor("#fffbeb"), borderPadding=6,
            ),
        ))
    story.append(Spacer(1, 16))

    # --- Triggered indicators ---
    story.append(Paragraph("Triggered Indicators", styles["SectionHeader"]))
    raw_indicators = record.get("triggered_indicators") or ""
    indicators = [i.strip() for i in raw_indicators.split(",") if i.strip()]

    if indicators:
        for ind in indicators:
            story.append(Paragraph(f"- {ind}", styles["BodyTextTight"]))
    else:
        story.append(Paragraph("No indicators triggered.", styles["BodyTextTight"]))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb"), thickness=1))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by AI Email Phishing Analyzer — automated triage tool. "
        "This report is intended to assist, not replace, analyst judgment.",
        styles["MetaText"],
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
