"""Tests for the persistent (SQLite-backed) job queue, atomic intake limit,
and crash recovery — the production-grade queue behaviour (Tahap 3/4).

These exercise ``Storage`` directly and need no web dependencies.
"""

from __future__ import annotations

import sqlite3

import pytest

from ojs_sast.service.storage import Storage


def _set_heartbeat(storage: Storage, scan_id: str, value) -> None:
    """Force a job's heartbeat_at (test helper; bypasses the whitelist)."""
    conn = sqlite3.connect(storage.db_path, isolation_level=None)
    try:
        conn.execute("UPDATE scans SET heartbeat_at=? WHERE scan_id=?", (value, scan_id))
    finally:
        conn.close()


# ── atomic claim ─────────────────────────────────────────────────────────── #

def test_claim_moves_queued_to_running_once(tmp_path):
    s = Storage(tmp_path / "d")
    assert s.try_begin_job("a", "k", 10) is not None
    s.mark_queued("a")

    first = s.claim_next_job("w1")
    second = s.claim_next_job("w2")

    assert first == "a"
    assert second is None, "a queued job must be claimable by exactly one worker"
    row = s.get("a")
    assert row["status"] == "running"
    assert row["worker_id"] == "w1"
    assert row["attempts"] == 1
    assert row["started_at"] and row["heartbeat_at"]


def test_receiving_jobs_are_not_claimable(tmp_path):
    s = Storage(tmp_path / "d")
    s.try_begin_job("a", "k", 10)  # left in 'receiving' (upload not finished)
    assert s.claim_next_job("w1") is None
    s.mark_queued("a")
    assert s.claim_next_job("w1") == "a"


def test_claim_is_fifo_by_created_at(tmp_path):
    s = Storage(tmp_path / "d")
    for sid in ("a", "b", "c"):
        s.try_begin_job(sid, "k", 10)
        s.mark_queued(sid)
    assert [s.claim_next_job("w") for _ in range(3)] == ["a", "b", "c"]


# ── atomic active-scan limit ─────────────────────────────────────────────── #

def test_try_begin_job_enforces_active_limit_atomically(tmp_path):
    s = Storage(tmp_path / "d")
    assert s.try_begin_job("a", "k", 2) is not None  # receiving (counts)
    s.mark_queued("a")                                # queued (counts)
    assert s.try_begin_job("b", "k", 2) is not None   # receiving (counts) -> 2 active
    # Third must be rejected: key already at the limit.
    assert s.try_begin_job("c", "k", 2) is None
    # A different key is unaffected.
    assert s.try_begin_job("d", "k2", 2) is not None


def test_active_limit_frees_up_when_job_finishes(tmp_path):
    s = Storage(tmp_path / "d")
    s.try_begin_job("a", "k", 1)
    s.mark_queued("a")
    assert s.try_begin_job("b", "k", 1) is None  # at limit
    s.update("a", status="done")                 # terminal -> no longer active
    assert s.try_begin_job("b", "k", 1) is not None


def test_count_active_includes_receiving_queued_running(tmp_path):
    s = Storage(tmp_path / "d")
    s.try_begin_job("a", "k", 10)               # receiving
    s.try_begin_job("b", "k", 10); s.mark_queued("b")   # queued
    s.try_begin_job("c", "k", 10); s.mark_queued("c"); s.claim_next_job("w")  # running
    s.try_begin_job("d", "k", 10); s.mark_queued("d"); s.update("d", status="done")  # done
    assert s.count_active("k") == 3


# ── crash recovery ───────────────────────────────────────────────────────── #

def _make_running_job(s: Storage, scan_id="a", *, with_source=True):
    job_dir = s.try_begin_job(scan_id, "k", 10)
    s.mark_queued(scan_id)
    s.claim_next_job("dead-worker")  # status=running, attempts=1, fresh heartbeat
    if with_source:
        (job_dir / "source.tar.gz").write_bytes(b"dummy")
    return job_dir


def test_recovery_leaves_live_jobs_alone(tmp_path):
    s = Storage(tmp_path / "d")
    _make_running_job(s, "a")  # heartbeat is fresh (just claimed)
    res = s.reclaim_orphaned(heartbeat_timeout_seconds=60, max_attempts=2)
    assert res == {"requeued": 0, "failed": 0}
    assert s.get("a")["status"] == "running"


def test_recovery_requeues_orphan_with_source(tmp_path):
    s = Storage(tmp_path / "d")
    _make_running_job(s, "a", with_source=True)
    _set_heartbeat(s, "a", "2000-01-01T00:00:00+00:00")  # stale -> worker died
    res = s.reclaim_orphaned(heartbeat_timeout_seconds=60, max_attempts=2)
    assert res == {"requeued": 1, "failed": 0}
    row = s.get("a")
    assert row["status"] == "queued"
    assert row["worker_id"] is None and row["heartbeat_at"] is None
    assert row["attempts"] == 1  # preserved; bumped again on the next claim


def test_recovery_errors_orphan_without_source(tmp_path):
    s = Storage(tmp_path / "d")
    _make_running_job(s, "a", with_source=False)
    _set_heartbeat(s, "a", "2000-01-01T00:00:00+00:00")
    res = s.reclaim_orphaned(heartbeat_timeout_seconds=60, max_attempts=2)
    assert res == {"requeued": 0, "failed": 1}
    row = s.get("a")
    assert row["status"] == "error"
    assert "stale" in (row["error"] or "")


def test_recovery_errors_when_attempts_exhausted(tmp_path):
    s = Storage(tmp_path / "d")
    _make_running_job(s, "a", with_source=True)  # attempts == 1
    _set_heartbeat(s, "a", "2000-01-01T00:00:00+00:00")
    # max_attempts=1 -> already exhausted, so error even though source is present.
    res = s.reclaim_orphaned(heartbeat_timeout_seconds=60, max_attempts=1)
    assert res == {"requeued": 0, "failed": 1}
    assert s.get("a")["status"] == "error"


def test_null_heartbeat_is_treated_as_orphan(tmp_path):
    s = Storage(tmp_path / "d")
    _make_running_job(s, "a", with_source=True)
    _set_heartbeat(s, "a", None)  # e.g. a row migrated from the old schema
    res = s.reclaim_orphaned(heartbeat_timeout_seconds=60, max_attempts=2)
    assert res == {"requeued": 1, "failed": 0}
    assert s.get("a")["status"] == "queued"


# ── migration of a pre-existing database ─────────────────────────────────── #

def test_migration_adds_queue_columns_to_old_db(tmp_path):
    data = tmp_path / "d"
    data.mkdir()
    db = data / "ojs_sast.db"
    # The original schema (before the persistent-queue columns were added).
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE scans ("
        "scan_id TEXT PRIMARY KEY, api_key_id TEXT NOT NULL, status TEXT NOT NULL, "
        "created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, ojs_version TEXT, "
        "source_sha256 TEXT, source_bytes INTEGER, finding_count INTEGER, error TEXT, "
        "job_dir TEXT NOT NULL, result_path TEXT, report_json_path TEXT, "
        "report_html_path TEXT, report_sarif_path TEXT);"
        "INSERT INTO scans (scan_id, api_key_id, status, created_at, job_dir) "
        "VALUES ('old', 'k', 'running', '2024-01-01T00:00:00+00:00', "
        "'" + str(data / "jobs" / "old") + "');"
    )
    conn.commit()
    conn.close()

    s = Storage(data)  # triggers _migrate
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(scans)")}
    assert {"worker_id", "attempts", "heartbeat_at"} <= cols
    # The migrated 'running' row has a NULL heartbeat -> recoverable (no source -> error).
    res = s.reclaim_orphaned(heartbeat_timeout_seconds=60, max_attempts=2)
    assert res["failed"] == 1
    assert s.get("old")["status"] == "error"
