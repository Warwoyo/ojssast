"""Tests for the decoupled scan-worker pool draining the persistent queue.

Mirrors the production topology: jobs are enqueued the way the API does it
(``try_begin_job`` + ``mark_queued``, *no* embedded worker), then a separate
``Worker`` pool claims and runs them. Needs no web dependencies.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from pathlib import Path

from ojs_sast.service.config import ServiceConfig
from ojs_sast.service.queue import JobQueue
from ojs_sast.service.storage import Storage
from ojs_sast.service.worker import Worker


def _enqueue_minimal_job(storage: Storage, scan_id: str, api_key_id: str = "k") -> Path:
    """Reserve + fill + queue a job exactly like the /scan endpoint does."""
    job_dir = storage.try_begin_job(scan_id, api_key_id, max_active=10)
    assert job_dir is not None
    with tarfile.open(job_dir / "source.tar.gz", "w:gz") as tar:
        data = b"<?php echo 'hello';\n"
        info = tarfile.TarInfo("source/index.php")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    meta = {
        "ojs_version": "3.3.0-13",
        "ojs_detected": False,
        "detection_markers": [],
        "source_label": "test",
        "scan_options": {"categories": ["source_code"], "min_severity": "INFO",
                         "formats": ["json"]},
        "source_archive": {"top_level_dir": "source", "sha256": None, "bytes": 0},
        "config_files": {},
        "upload_manifest": None,
    }
    (job_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    storage.mark_queued(scan_id)
    return job_dir


def _wait_terminal(storage: Storage, scan_id: str, tries: int = 200):
    for _ in range(tries):
        row = storage.get(scan_id)
        if row and row["status"] in ("done", "error"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not finish in time")


def _config(tmp_path):
    return ServiceConfig(
        data_dir=tmp_path / "data",
        poll_interval_seconds=0.05,
        reclaim_interval_seconds=1000.0,  # don't let recovery interfere here
    )


def test_worker_pool_claims_and_completes_job(tmp_path, ruleset):
    storage = Storage(tmp_path / "data")
    cfg = _config(tmp_path)
    queue = JobQueue(storage, poll_interval=0.05)
    pool = Worker(storage, queue, cfg, ruleset=ruleset, concurrency=1)

    job_dir = _enqueue_minimal_job(storage, "pool-1")
    pool.start()
    try:
        row = _wait_terminal(storage, "pool-1")
    finally:
        pool.stop()

    assert row["status"] == "done", row.get("error")
    assert (job_dir / "result.json").is_file()
    assert row["worker_id"] is not None     # a pool worker claimed it
    assert row["attempts"] == 1
    # Sandbox cleanup ran.
    assert not (job_dir / "source.tar.gz").exists()
    assert not (job_dir / "extracted").exists()


def test_worker_pool_drains_multiple_jobs(tmp_path, ruleset):
    storage = Storage(tmp_path / "data")
    cfg = _config(tmp_path)
    queue = JobQueue(storage, poll_interval=0.05)
    pool = Worker(storage, queue, cfg, ruleset=ruleset, concurrency=2)

    ids = [f"pool-{i}" for i in range(5)]
    for sid in ids:
        _enqueue_minimal_job(storage, sid)

    pool.start()
    try:
        rows = [_wait_terminal(storage, sid) for sid in ids]
    finally:
        pool.stop()

    assert all(r["status"] == "done" for r in rows), [r["error"] for r in rows]


def test_pool_stop_is_clean_when_idle(tmp_path, ruleset):
    storage = Storage(tmp_path / "data")
    pool = Worker(storage, JobQueue(storage, poll_interval=0.05), _config(tmp_path),
                  ruleset=ruleset, concurrency=2)
    pool.start()
    pool.stop()  # must return promptly without hanging
    assert pool._threads == []
