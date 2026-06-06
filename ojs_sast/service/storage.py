"""Filesystem + SQLite storage for scan jobs (pure stdlib).

Layout::

    <data_dir>/
      ojs_sast.db
      jobs/<scan_id>/
        source.tar.gz      (removed after the job runs)
        meta.json
        extracted/         (removed after the job runs)
        result.json
        reports/

Each method opens a short-lived SQLite connection, so the request thread and the
worker thread never share one.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id           TEXT PRIMARY KEY,
    api_key_id        TEXT NOT NULL,
    status            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    started_at        TEXT,
    finished_at       TEXT,
    ojs_version       TEXT,
    source_sha256     TEXT,
    source_bytes      INTEGER,
    finding_count     INTEGER,
    error             TEXT,
    job_dir           TEXT NOT NULL,
    result_path       TEXT,
    report_json_path  TEXT,
    report_html_path  TEXT,
    report_sarif_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_active ON scans(api_key_id, status);
"""

# Columns callers may update (guards against accidental SQL via column names).
_UPDATABLE = {
    "status", "started_at", "finished_at", "ojs_version", "source_sha256",
    "source_bytes", "finding_count", "error", "result_path",
    "report_json_path", "report_html_path", "report_sarif_path",
}

_STATUS_FIELDS = (
    "scan_id", "status", "created_at", "started_at", "finished_at",
    "error", "ojs_version", "finding_count",
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Storage:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.jobs_dir = self.data_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "ojs_sast.db"
        self._init_db()

    # ----------------------------------------------------------------- #
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    # ----------------------------------------------------------------- #
    def job_dir(self, scan_id: str) -> Path:
        return self.jobs_dir / scan_id

    def create_job(self, scan_id: str, api_key_id: str) -> Path:
        job_dir = self.job_dir(scan_id)
        (job_dir / "reports").mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO scans (scan_id, api_key_id, status, created_at, job_dir) "
                "VALUES (?, ?, 'queued', ?, ?)",
                (scan_id, api_key_id, _utcnow(), str(job_dir)),
            )
            conn.commit()
        finally:
            conn.close()
        return job_dir

    def update(self, scan_id: str, **fields: Any) -> None:
        cols = [c for c in fields if c in _UPDATABLE]
        if not cols:
            return
        assignments = ", ".join(f"{c} = ?" for c in cols)
        values = [fields[c] for c in cols]
        values.append(scan_id)
        conn = self._connect()
        try:
            conn.execute(f"UPDATE scans SET {assignments} WHERE scan_id = ?", values)
            conn.commit()
        finally:
            conn.close()

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def status_view(self, scan_id: str) -> Optional[Dict[str, Any]]:
        row = self.get(scan_id)
        if row is None:
            return None
        return {k: row.get(k) for k in _STATUS_FIELDS}

    def count_active(self, api_key_id: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM scans "
                "WHERE api_key_id = ? AND status IN ('queued', 'running')",
                (api_key_id,),
            ).fetchone()
        finally:
            conn.close()
        return int(row["c"]) if row else 0
