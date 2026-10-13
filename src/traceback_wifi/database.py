"""Local SQLite persistence. Uses per-thread connections, WAL for readers."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Assessment, Sample


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_samples_time ON samples(timestamp);
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    fingerprint TEXT NOT NULL,
                    sample_id INTEGER NOT NULL,
                    assessment TEXT NOT NULL,
                    FOREIGN KEY(sample_id) REFERENCES samples(id)
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(started_at);
                CREATE TABLE IF NOT EXISTS challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    ended_at TEXT,
                    before_json TEXT NOT NULL,
                    after_json TEXT,
                    comment TEXT
                );
            """)

    def store_sample(self, sample: Sample) -> int:
        with self._connect() as db:
            cursor = db.execute("INSERT INTO samples(timestamp,payload) VALUES (?,?)",
                                (sample.timestamp, json.dumps(sample.to_dict())))
            return int(cursor.lastrowid)

    def recent_samples(self, limit: int = 50, after: str | None = None) -> list[Sample]:
        with self._connect() as db:
            if after:
                rows = db.execute("SELECT payload FROM samples WHERE timestamp > ? "
                                  "ORDER BY id DESC LIMIT ?", (after, limit)).fetchall()
            else:
                rows = db.execute("SELECT payload FROM samples ORDER BY id DESC LIMIT ?",
                                  (limit,)).fetchall()
        return [Sample.from_dict(json.loads(row["payload"])) for row in rows][::-1]

    def incident_context(self, sample_id: int, limit: int = 8) -> list[Sample]:
        """Actual observed samples up to and including the incident-opening sample."""
        with self._connect() as db:
            rows = db.execute("SELECT payload FROM samples WHERE id <= ? "
                              "ORDER BY id DESC LIMIT ?", (sample_id, limit)).fetchall()
        return [Sample.from_dict(json.loads(r["payload"])) for r in rows][::-1]

    def open_incident(self, sample_id: int, sample: Sample, assessment: Assessment,
                      fingerprint: str) -> int:
        with self._connect() as db:
            c = db.execute("INSERT INTO incidents(started_at,fingerprint,sample_id,assessment) "
                           "VALUES(?,?,?,?)", (sample.timestamp, fingerprint, sample_id,
                                                  json.dumps(assessment.to_dict())))
            return int(c.lastrowid)

    def close_incident(self, incident_id: int, timestamp: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE incidents SET ended_at=? WHERE id=? AND ended_at IS NULL",
                       (timestamp, incident_id))

    def open_incident_id(self) -> int | None:
        with self._connect() as db:
            row = db.execute("SELECT id FROM incidents WHERE ended_at IS NULL "
                             "ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None

    def repeat_count(self, fingerprint: str) -> int:
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*) AS n FROM incidents WHERE fingerprint=?", (fingerprint,)).fetchone()
        return int(row["n"])

    def incidents(self, limit: int = 100) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(row), "assessment": json.loads(row["assessment"])} for row in rows]

    def save_challenge(self, before: list[Sample]) -> int:
        from .models import utc_now
        with self._connect() as db:
            c = db.execute("INSERT INTO challenges(created_at,before_json) VALUES(?,?)",
                           (utc_now(), json.dumps([s.to_dict() for s in before])))
            return int(c.lastrowid)

    def finish_challenge(self, challenge_id: int, after: list[Sample], comment: str) -> None:
        from .models import utc_now
        with self._connect() as db:
            db.execute("UPDATE challenges SET ended_at=?,after_json=?,comment=? "
                       "WHERE id=? AND ended_at IS NULL",
                       (utc_now(), json.dumps([s.to_dict() for s in after]),
                        comment[:1000], challenge_id))

    def challenges(self, limit: int = 20) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM challenges ORDER BY id DESC LIMIT ?",
                              (limit,)).fetchall()
        return [dict(r) for r in rows]

    def prune_samples(self, days: int = 7) -> None:
        # Incidents refer to sample IDs; never delete referenced incident evidence.
        threshold = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        with self._connect() as db:
            db.execute("DELETE FROM samples WHERE timestamp < ? "
                       "AND id NOT IN (SELECT sample_id FROM incidents)", (threshold,))
