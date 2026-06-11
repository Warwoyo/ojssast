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

The SQLite ``scans`` table doubles as a **persistent, shared job queue**: the
``status`` column carries the job through ``receiving`` → ``queued`` →
``running`` → ``done``/``error``. Because the queue lives in the database (not
in a per-process :class:`queue.Queue`), several gunicorn API workers and several
separate scan-worker processes can share one queue and survive restarts.

Concurrency model:

* Each method opens a short-lived connection in **autocommit** mode
  (``isolation_level=None``) so the multi-statement claim/intake helpers can use
  explicit ``BEGIN IMMEDIATE`` transactions. ``BEGIN IMMEDIATE`` takes the
  write lock up front, which serialises claimers/intake across *processes* and
  makes ``try_begin_job`` and ``claim_next_job`` atomic.
* WAL journling lets API readers and the worker writer proceed concurrently.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    report_sarif_path TEXT,
    worker_id         TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0,
    heartbeat_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_active ON scans(api_key_id, status);
CREATE INDEX IF NOT EXISTS idx_scans_queue ON scans(status, created_at);
"""

# Columns added after the original schema; applied to pre-existing databases by
# _migrate() so upgrades don't require a manual ALTER.
_ADDED_COLUMNS = (
    ("worker_id", "worker_id TEXT"),
    ("attempts", "attempts INTEGER NOT NULL DEFAULT 0"),
    ("heartbeat_at", "heartbeat_at TEXT"),
)

# Statuses that count against a key's active-scan limit and that the persistent
# queue considers "in flight" (i.e. not a terminal done/error).
_ACTIVE_STATUSES = ("receiving", "queued", "running")

# Columns callers may update (guards against accidental SQL via column names).
# Queue-management columns (status transitions, worker_id, attempts, heartbeat)
# are written only through the dedicated atomic helpers below.
_UPDATABLE = {
    "status", "started_at", "finished_at", "ojs_version", "source_sha256",
    "source_bytes", "finding_count", "error", "result_path",
    "report_json_path", "report_html_path", "report_sarif_path",
}

_STATUS_FIELDS = (
    "scan_id", "status", "created_at", "started_at", "finished_at",
    "error", "ojs_version", "finding_count", "attempts",
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
        # isolation_level=None -> autocommit; we manage transactions explicitly
        # for the atomic claim/intake helpers. timeout busy-waits on the write
        # lock so contended claimers serialise instead of failing.
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            self._migrate(conn)
        finally:
            conn.close()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        for name, ddl in _ADDED_COLUMNS:
            if name not in existing:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {ddl}")

    # ----------------------------------------------------------------- #
    def job_dir(self, scan_id: str) -> Path:
        return self.jobs_dir / scan_id

    def create_job(self, scan_id: str, api_key_id: str) -> Path:
        """Insert a job directly as ``queued`` (used by tests / direct callers).

        The HTTP intake path uses :meth:`try_begin_job` + :meth:`mark_queued`
        instead, so a worker never claims a job whose upload is still arriving.
        """
        job_dir = self.job_dir(scan_id)
        (job_dir / "reports").mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO scans (scan_id, api_key_id, status, created_at, job_dir) "
                "VALUES (?, ?, 'queued', ?, ?)",
                (scan_id, api_key_id, _utcnow(), str(job_dir)),
            )
        finally:
            conn.close()
        return job_dir

    def try_begin_job(self, scan_id: str, api_key_id: str,
                      max_active: int) -> Optional[Path]:
        """Atomically enforce the per-key active limit and reserve a job slot.

        Counts in-flight scans (``receiving``/``queued``/``running``) for the
        key and, only if below ``max_active``, inserts the job as ``receiving``
        — all inside one ``BEGIN IMMEDIATE`` transaction, so concurrent requests
        (even across processes) can't both slip past the limit. Returns the job
        directory, or ``None`` if the key is at its limit.

        ``receiving`` is intentionally not claimable: the worker pool only picks
        up ``queued`` jobs, so the upload finishes (then :meth:`mark_queued`)
        before any worker can touch it.
        """
        placeholders = ", ".join("?" for _ in _ACTIVE_STATUSES)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"SELECT COUNT(*) AS c FROM scans "
                f"WHERE api_key_id = ? AND status IN ({placeholders})",
                (api_key_id, *_ACTIVE_STATUSES),
            ).fetchone()
            if int(row["c"]) >= max_active:
                conn.execute("ROLLBACK")
                return None
            job_dir = self.job_dir(scan_id)
            (job_dir / "reports").mkdir(parents=True, exist_ok=True)
            conn.execute(
                "INSERT INTO scans (scan_id, api_key_id, status, created_at, job_dir) "
                "VALUES (?, ?, 'receiving', ?, ?)",
                (scan_id, api_key_id, _utcnow(), str(job_dir)),
            )
            conn.execute("COMMIT")
            return job_dir
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def mark_queued(self, scan_id: str, source_sha256: Optional[str] = None,
                    source_bytes: Optional[int] = None) -> None:
        """Promote a ``receiving`` job to ``queued`` (claimable by the pool)."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE scans SET status='queued', "
                "source_sha256=COALESCE(?, source_sha256), "
                "source_bytes=COALESCE(?, source_bytes) "
                "WHERE scan_id=? AND status='receiving'",
                (source_sha256, source_bytes, scan_id),
            )
        finally:
            conn.close()

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
        finally:
            conn.close()

    # --- persistent-queue operations --------------------------------- #
    def claim_next_job(self, worker_id: str) -> Optional[str]:
        """Atomically claim the oldest ``queued`` job for ``worker_id``.

        Moves it to ``running`` (recording started_at, worker_id, a fresh
        heartbeat, and bumping ``attempts``) inside a ``BEGIN IMMEDIATE``
        transaction so no two workers — in this process or another — claim the
        same job. Returns the claimed scan_id, or ``None`` if the queue is empty.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT scan_id FROM scans WHERE status='queued' "
                "ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            scan_id = row["scan_id"]
            now = _utcnow()
            conn.execute(
                "UPDATE scans SET status='running', started_at=?, heartbeat_at=?, "
                "worker_id=?, attempts=attempts+1 WHERE scan_id=? AND status='queued'",
                (now, now, worker_id, scan_id),
            )
            conn.execute("COMMIT")
            return scan_id
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def heartbeat(self, scan_id: str) -> None:
        """Mark a running job as still alive (called periodically by its worker)."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE scans SET heartbeat_at=? WHERE scan_id=? AND status='running'",
                (_utcnow(), scan_id),
            )
        finally:
            conn.close()

    def reclaim_orphaned(self, heartbeat_timeout_seconds: float,
                         max_attempts: int) -> Dict[str, int]:
        """Recover jobs left ``running`` by a worker/process that died.

        A running job is considered orphaned when its heartbeat is older than
        ``heartbeat_timeout_seconds`` (or never set). Live workers refresh their
        heartbeat, so this is safe to run from every worker process: a job being
        actively scanned elsewhere is left alone.

        Policy per orphan:

        * source archive still present *and* ``attempts < max_attempts`` →
          requeue (back to ``queued``) so it is retried;
        * otherwise → mark ``error`` (stale).

        Returns ``{"requeued": n, "failed": m}``.
        """
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(seconds=heartbeat_timeout_seconds)).isoformat()
        requeued = failed = 0
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT scan_id, job_dir, attempts FROM scans "
                "WHERE status='running' AND (heartbeat_at IS NULL OR heartbeat_at < ?)",
                (cutoff,),
            ).fetchall()
            for r in rows:
                source = Path(r["job_dir"]) / "source.tar.gz"
                if source.is_file() and int(r["attempts"]) < max_attempts:
                    conn.execute(
                        "UPDATE scans SET status='queued', started_at=NULL, "
                        "heartbeat_at=NULL, worker_id=NULL, error=NULL "
                        "WHERE scan_id=? AND status='running'",
                        (r["scan_id"],),
                    )
                    requeued += 1
                else:
                    conn.execute(
                        "UPDATE scans SET status='error', finished_at=?, error=? "
                        "WHERE scan_id=? AND status='running'",
                        (_utcnow(),
                         "stale: worker died before completion (no heartbeat)",
                         r["scan_id"]),
                    )
                    failed += 1
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"requeued": requeued, "failed": failed}

    # ----------------------------------------------------------------- #
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
        placeholders = ", ".join("?" for _ in _ACTIVE_STATUSES)
        conn = self._connect()
        try:
            row = conn.execute(
                f"SELECT COUNT(*) AS c FROM scans "
                f"WHERE api_key_id = ? AND status IN ({placeholders})",
                (api_key_id, *_ACTIVE_STATUSES),
            ).fetchone()
        finally:
            conn.close()
        return int(row["c"]) if row else 0
