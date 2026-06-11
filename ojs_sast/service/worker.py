"""Background scan-worker pool for the service.

Each worker thread pulls a scan id from the **persistent, SQLite-backed queue**
(:class:`~ojs_sast.service.queue.JobQueue`), safely extracts the source archive
into a sandbox, runs ``Orchestrator.run_bundle``, persists the result and
reports, and cleans up the sandbox regardless of success or failure.

This pool is designed to run either:

* embedded in the dev/all-in-one server (``ojs-sast-service start``), or
* as one or more **separate processes** (``ojs-sast-service worker``), scaled
  via a systemd template, sharing one queue with the gunicorn API.

Reliability features (vs. the original single in-memory thread):

* **Atomic claim** — :meth:`Storage.claim_next_job` hands a job to exactly one
  worker, so multiple worker processes never double-run a scan.
* **Heartbeat** — while a job runs, a side thread refreshes ``heartbeat_at`` so
  other workers can tell the job is alive.
* **Recovery** — on start and periodically, :meth:`Storage.reclaim_orphaned`
  requeues (or fails) jobs whose worker died mid-scan.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from ..models import Severity
from ..models.bundle import ScanBundle, resolve_source_root
from ..models.report import ScanReport
from ..orchestrator import Orchestrator
from ..reporters import (generate_html_report, generate_json_report,
                         generate_sarif_report)
from ..ruleset.loader import Ruleset, load_ruleset
from .auth import write_audit
from .extract import safe_extract_archive
from .queue import JobQueue
from .storage import Storage

logger = logging.getLogger("ojs_sast.service.worker")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_reports(result, out_dir: Path) -> Dict[str, Path]:
    """Generate the three reports into a flat directory (no timestamp subfolder)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    report = ScanReport.from_scan_result(result)
    out = str(out_dir)
    return {
        "json": Path(generate_json_report(report, out)),
        "html": Path(generate_html_report(report, out)),
        "sarif": Path(generate_sarif_report(report, out)),
    }


class Worker:
    def __init__(self, storage: Storage, job_queue: JobQueue, config,
                 ruleset: Optional[Ruleset] = None, *,
                 concurrency: Optional[int] = None,
                 worker_id: Optional[str] = None):
        self.storage = storage
        self.queue = job_queue
        self.config = config
        self.ruleset = ruleset or load_ruleset()

        self.concurrency = int(
            concurrency if concurrency is not None
            else getattr(config, "worker_concurrency", 1)) or 1
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"
        self.poll_interval = float(getattr(config, "poll_interval_seconds", 0.5))
        self.heartbeat_interval = float(getattr(config, "heartbeat_interval_seconds", 15.0))
        self.heartbeat_timeout = float(getattr(config, "heartbeat_timeout_seconds", 60.0))
        self.reclaim_interval = float(getattr(config, "reclaim_interval_seconds", 30.0))
        self.max_attempts = int(getattr(config, "max_attempts", 2))

        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if self._threads:
            return
        # Requeue jobs orphaned by a previous crash before taking new work.
        self.recover()
        for i in range(self.concurrency):
            t = threading.Thread(
                target=self._loop, name=f"ojs-sast-worker-{i}",
                args=(f"{self.worker_id}#{i}",), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self.queue.stop()
        for t in self._threads:
            t.join(timeout=30)
        self._threads = []

    def recover(self) -> Dict[str, int]:
        try:
            res = self.storage.reclaim_orphaned(self.heartbeat_timeout, self.max_attempts)
            if res["requeued"] or res["failed"]:
                logger.info("recovery: requeued=%d failed=%d",
                            res["requeued"], res["failed"])
            return res
        except Exception:  # pragma: no cover - defensive
            logger.exception("recovery (reclaim_orphaned) failed")
            return {"requeued": 0, "failed": 0}

    # ----------------------------------------------------------------- #
    def _loop(self, worker_id: str) -> None:
        next_reclaim = 0.0
        while not self.queue.stopped():
            now = time.monotonic()
            if now >= next_reclaim:
                self.recover()
                next_reclaim = now + self.reclaim_interval

            scan_id: Optional[str] = None
            try:
                scan_id = self.queue.claim(worker_id)
            except Exception:  # pragma: no cover - defensive
                logger.exception("claim failed")

            if scan_id is None:
                self.queue.wait(self.poll_interval)
                continue
            self._process_with_heartbeat(scan_id)

    def _process_with_heartbeat(self, scan_id: str) -> None:
        done = threading.Event()

        def _beat() -> None:
            while not done.wait(self.heartbeat_interval):
                try:
                    self.storage.heartbeat(scan_id)
                except Exception:  # pragma: no cover - defensive
                    logger.exception("heartbeat failed for %s", scan_id)

        hb = threading.Thread(target=_beat, name=f"hb-{scan_id[:8]}", daemon=True)
        hb.start()
        try:
            self.process_job(scan_id)
        except Exception:  # pragma: no cover - process_job handles its own errors
            logger.exception("worker crashed processing %s", scan_id)
        finally:
            done.set()
            hb.join(timeout=5)

    def process_job(self, scan_id: str) -> None:
        job_dir = self.storage.job_dir(scan_id)
        source = job_dir / "source.tar.gz"
        meta_path = job_dir / "meta.json"
        extracted = job_dir / "extracted"
        self.storage.update(scan_id, status="running", started_at=_utcnow())

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            scan_options = meta.get("scan_options") or {}
            categories = scan_options.get("categories")
            min_severity_raw = scan_options.get("min_severity", "INFO")
            # formats is read for future use; all 3 formats are always generated.
            valid_categories = {"source_code", "config", "upload_directory"}
            if categories:
                categories = [c for c in categories if c in valid_categories]

            try:
                min_severity = Severity.from_str(min_severity_raw)
            except ValueError:
                self.storage.update(scan_id, status="error", finished_at=_utcnow(),
                                    error=f"invalid min_severity: {min_severity_raw!r}")
                write_audit(self.config.audit_log_path,
                            {"scan_id": scan_id, "status": "error",
                             "error": "invalid_min_severity"})
                return

            safe_extract_archive(
                source, extracted,
                max_files=self.config.max_files_per_archive,
                max_total_bytes=self.config.max_total_extracted_bytes,
                max_file_bytes=self.config.max_file_bytes,
            )
            source_root = resolve_source_root(extracted, meta)
            bundle = ScanBundle.from_meta(meta, source_root)

            orch = Orchestrator(
                source_root or extracted,
                ruleset=self.ruleset,
                min_severity=min_severity,
                categories=categories or None,
            )
            result = orch.run_bundle(bundle)

            result_path = job_dir / "result.json"
            result_path.write_text(
                json.dumps(result.to_report_dict(), indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            reports = _generate_reports(result, job_dir / "reports")

            self.storage.update(
                scan_id, status="done", finished_at=_utcnow(),
                ojs_version=result.metadata.get("ojs_version"),
                finding_count=len(result.findings),
                source_sha256=bundle.source_archive_sha256,
                source_bytes=bundle.source_archive_bytes,
                result_path=str(result_path),
                report_json_path=str(reports["json"]),
                report_html_path=str(reports["html"]),
                report_sarif_path=str(reports["sarif"]),
            )
            write_audit(self.config.audit_log_path,
                        {"scan_id": scan_id, "status": "done",
                         "findings": len(result.findings)})
            logger.info("scan %s done: %d findings", scan_id, len(result.findings))
        except Exception as exc:
            logger.exception("scan %s failed", scan_id)
            self.storage.update(scan_id, status="error", finished_at=_utcnow(),
                                error=str(exc)[:500])
            write_audit(self.config.audit_log_path,
                        {"scan_id": scan_id, "status": "error",
                         "error": type(exc).__name__})
        finally:
            # Sandbox cleanup: drop the extracted tree and the uploaded archive,
            # keep result.json + reports.
            shutil.rmtree(extracted, ignore_errors=True)
            try:
                source.unlink()
            except OSError:  # pragma: no cover
                pass
