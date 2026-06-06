"""Background job runner for the service.

A single daemon thread pops scan ids from the queue, safely extracts the source
archive into a sandbox, runs ``Orchestrator.run_bundle``, persists the result
and reports, and then cleans up the sandbox (the extracted tree and the uploaded
archive) regardless of success or failure.
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
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
                 ruleset: Optional[Ruleset] = None):
        self.storage = storage
        self.queue = job_queue
        self.config = config
        self.ruleset = ruleset or load_ruleset()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._loop, name="ojs-sast-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.queue.stop()
        if self._thread:
            self._thread.join(timeout=30)

    # ----------------------------------------------------------------- #
    def _loop(self) -> None:
        while True:
            scan_id = self.queue.get()
            if scan_id is None:  # shutdown sentinel
                self.queue.task_done()
                break
            try:
                self.process_job(scan_id)
            except Exception:  # pragma: no cover - defensive; process_job handles its own
                logger.exception("worker crashed processing %s", scan_id)
            finally:
                self.queue.task_done()

    def process_job(self, scan_id: str) -> None:
        job_dir = self.storage.job_dir(scan_id)
        source = job_dir / "source.tar.gz"
        meta_path = job_dir / "meta.json"
        extracted = job_dir / "extracted"
        self.storage.update(scan_id, status="running", started_at=_utcnow())

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            safe_extract_archive(
                source, extracted,
                max_files=self.config.max_files_per_archive,
                max_total_bytes=self.config.max_total_extracted_bytes,
                max_file_bytes=self.config.max_file_bytes,
            )
            source_root = resolve_source_root(extracted, meta)
            bundle = ScanBundle.from_meta(meta, source_root)

            # Honour scan_options from meta.json.
            scan_options = meta.get("scan_options") or {}

            min_severity_raw = scan_options.get("min_severity", "INFO")
            try:
                min_severity = Severity.from_str(min_severity_raw)
            except ValueError:
                raise ValueError(
                    f"Invalid min_severity in meta.json: {min_severity_raw!r}")

            categories = scan_options.get("categories")
            valid_categories = {"source_code", "config", "upload_directory"}
            if categories is not None:
                categories = [c for c in categories if c in valid_categories]
                if not categories:
                    categories = None

            orch = Orchestrator(
                source_root or extracted,
                ruleset=self.ruleset,
                min_severity=min_severity,
                categories=categories,
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
