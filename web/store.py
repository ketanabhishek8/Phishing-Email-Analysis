"""SQLite persistence for analysed emails (the dashboard's history)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    filename TEXT NOT NULL,
    subject TEXT NOT NULL,
    sender TEXT NOT NULL,
    score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    report_json TEXT NOT NULL
)
"""


class Store:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, filename: str, report: dict) -> int:
        summary = report.get("summary", {})
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO analyses (created_at, filename, subject, sender, score, verdict, report_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    filename,
                    summary.get("subject", ""),
                    summary.get("from", ""),
                    int(report.get("score", 0)),
                    report.get("verdict", ""),
                    json.dumps(report),
                ),
            )
            return int(cur.lastrowid)

    def get(self, analysis_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["report"] = json.loads(data.pop("report_json"))
        return data

    def list(self, limit: int = 200) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, filename, subject, sender, score, verdict "
                "FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        counts = {"total": 0, "Clean": 0, "Suspicious": 0, "Likely phishing": 0}
        with self._connect() as conn:
            for row in conn.execute("SELECT verdict, COUNT(*) AS n FROM analyses GROUP BY verdict"):
                counts[row["verdict"]] = row["n"]
                counts["total"] += row["n"]
        return counts
