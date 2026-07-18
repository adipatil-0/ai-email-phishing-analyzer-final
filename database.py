import sqlite3
from contextlib import contextmanager

DB_PATH = "phishing_analyzer.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyzed_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    subject TEXT,
    heuristic_score REAL,
    ai_score REAL,
    final_score REAL,
    verdict TEXT,
    triggered_indicators TEXT,
    analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute(SCHEMA)


def save_analysis(record: dict) -> int:
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO analyzed_emails
               (sender, subject, heuristic_score, ai_score, final_score, verdict, triggered_indicators)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                record.get("sender"),
                record.get("subject"),
                record.get("heuristic_score"),
                record.get("ai_score"),
                record.get("final_score"),
                record.get("verdict"),
                ",".join(record.get("triggered_indicators", [])),
            ),
        )
        return cursor.lastrowid


def get_by_id(record_id: int):
    """Used by Day 7 PDF export — returns a single record dict, or None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM analyzed_emails WHERE id = ?", (record_id,)
        ).fetchone()
        return dict(row) if row else None


def get_history(limit: int = 50, verdict: str = None, search: str = None):
    query = "SELECT * FROM analyzed_emails WHERE 1=1"
    params = []

    if verdict:
        query += " AND verdict = ?"
        params.append(verdict)

    if search:
        query += " AND (sender LIKE ? OR subject LIKE ?)"
        like = f"%{search}%"
        params += [like, like]

    query += " ORDER BY analyzed_at DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_stats():
    """Counts for the history page stats bar. Unfiltered — always reflects the full table."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT
                   COUNT(*) AS total,
                   SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) AS malicious,
                   SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                   SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) AS clean
               FROM analyzed_emails"""
        ).fetchone()
        stats = dict(row)
        # SUM() over an empty table returns NULL, not 0 — normalize for the template
        for key in ("total", "malicious", "suspicious", "clean"):
            stats[key] = stats[key] or 0
        return stats
