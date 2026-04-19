"""SQLite store for local threat cache and detection logs."""

import json
import os
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(os.environ.get("CLAWGUARD_DB_PATH", Path(__file__).parent / "clawguard.db"))

# Use /tmp on Vercel (writable), fall back to the managed skill dir locally.
if os.environ.get("VERCEL"):
    DB_PATH = Path("/tmp/clawguard.db")


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS threat_cache (
            pattern_hash TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            sample_redacted TEXT,
            reporter TEXT,
            block_number INTEGER,
            cached_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detection_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            tool_name TEXT,
            modality TEXT,
            verdict TEXT NOT NULL,
            confidence REAL,
            reasons TEXT,
            content_hash TEXT,
            content_preview TEXT,
            source_manifest TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_detection_ts ON detection_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_cache(category);
    """)
    conn.commit()
    conn.close()


def cache_threat(pattern_hash: str, category: str, sample_redacted: str,
                 reporter: str = "", block_number: int = 0):
    conn = get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO threat_cache VALUES (?, ?, ?, ?, ?, ?)",
        (pattern_hash, category, sample_redacted, reporter, block_number, int(time.time()))
    )
    conn.commit()
    conn.close()


def check_threat_cache(pattern_hash: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM threat_cache WHERE pattern_hash = ?", (pattern_hash,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def log_detection(tool_name: str, modality: str, verdict: str, confidence: float,
                  reasons: list[str], content_hash: str, content_preview: str,
                  source_manifest: dict | None = None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO detection_log (timestamp, tool_name, modality, verdict, confidence, "
        "reasons, content_hash, content_preview, source_manifest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(time.time()), tool_name, modality, verdict, confidence,
         json.dumps(reasons), content_hash, content_preview[:500],
         json.dumps(source_manifest) if source_manifest else None)
    )
    conn.commit()
    conn.close()


def get_recent_detections(limit: int = 50) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM detection_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    results = []
    for row in rows:
        d = dict(row)
        d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
        d["source_manifest"] = json.loads(d["source_manifest"]) if d["source_manifest"] else None
        results.append(d)
    return results


def get_stats() -> dict:
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM detection_log").fetchone()[0]
    by_verdict = dict(conn.execute(
        "SELECT verdict, COUNT(*) FROM detection_log GROUP BY verdict"
    ).fetchall())
    by_modality = dict(conn.execute(
        "SELECT modality, COUNT(*) FROM detection_log GROUP BY modality"
    ).fetchall())
    cutoff = int(time.time()) - 86400
    hourly = conn.execute(
        "SELECT (timestamp / 3600) * 3600 as hour, COUNT(*) "
        "FROM detection_log WHERE timestamp > ? AND verdict != 'pass' "
        "GROUP BY hour ORDER BY hour",
        (cutoff,)
    ).fetchall()
    conn.close()
    return {
        "total_scans": total,
        "by_verdict": by_verdict,
        "by_modality": by_modality,
        "hourly_blocks": [{"hour": r[0], "count": r[1]} for r in hourly],
        "cached_threats": get_cached_threat_count(),
    }


def get_cached_threat_count() -> int:
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) FROM threat_cache").fetchone()[0]
    conn.close()
    return count


def get_all_cached_threats(limit: int = 100) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM threat_cache ORDER BY cached_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


init_db()
