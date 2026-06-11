"""Service configuration (``service.yml``).

Loaded with :func:`yaml.safe_load` into a plain dataclass (no pydantic), so it
works on the bare install. API keys are stored as **sha256 hashes only** — the
raw keys are never present in config or logs.

Besides the original intake limits, this also carries the **worker-pool /
persistent-queue** knobs (concurrency, poll interval, heartbeat + recovery
timings). Defaults are tuned for a small VPS (≈4 vCPU / 16 GB): the gunicorn
API workers are configured separately (see ``deploy/gunicorn.conf.py``), while
``worker_concurrency`` controls threads *per* scan-worker process — production
typically runs one process per core via the systemd template instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def _normalize_hash(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("sha256:"):
        value = value[len("sha256:"):]
    return value.lower()


@dataclass
class ServiceConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    data_dir: Path = Path("/var/lib/ojs-sast")
    # Maps sha256(key) hex -> agent_id (or None).
    api_keys: Dict[str, Optional[str]] = field(default_factory=dict)
    ip_allowlist: List[str] = field(default_factory=list)
    max_upload_bytes: int = 100 * 1024 * 1024
    max_files_per_archive: int = 50_000
    max_total_extracted_bytes: int = 500 * 1024 * 1024
    max_file_bytes: int = 50 * 1024 * 1024
    max_active_scans_per_key: int = 3
    audit_log_path: Optional[Path] = None

    # --- worker pool / persistent queue tuning --------------------------- #
    # Threads per scan-worker process. Keep at 1 and scale processes (systemd
    # template) for true multi-core parallelism (Python's GIL limits CPU-bound
    # threads); raise only for I/O-bound experimentation.
    worker_concurrency: int = 1
    # How often an idle worker polls the queue for new jobs (seconds).
    poll_interval_seconds: float = 0.5
    # A running job refreshes its heartbeat this often (seconds)...
    heartbeat_interval_seconds: float = 15.0
    # ...and is considered orphaned (worker died) after this long without one.
    heartbeat_timeout_seconds: float = 60.0
    # How often each worker scans for orphaned jobs to recover (seconds).
    reclaim_interval_seconds: float = 30.0
    # Max times a job is (re)attempted before recovery gives up and errors it.
    max_attempts: int = 2

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceConfig":
        data = dict(data or {})
        api_keys: Dict[str, Optional[str]] = {}
        for item in data.get("api_keys") or []:
            if isinstance(item, str):
                api_keys[_normalize_hash(item)] = None
            elif isinstance(item, dict):
                kh = item.get("key_hash") or item.get("hash")
                if kh:
                    api_keys[_normalize_hash(str(kh))] = (
                        item.get("agent_id") or item.get("key_id"))
        audit = data.get("audit_log_path")
        return cls(
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 8000)),
            data_dir=Path(data.get("data_dir", "/var/lib/ojs-sast")),
            api_keys=api_keys,
            ip_allowlist=list(data.get("ip_allowlist") or []),
            max_upload_bytes=int(data.get("max_upload_bytes", 100 * 1024 * 1024)),
            max_files_per_archive=int(data.get("max_files_per_archive", 50_000)),
            max_total_extracted_bytes=int(
                data.get("max_total_extracted_bytes", 500 * 1024 * 1024)),
            max_file_bytes=int(data.get("max_file_bytes", 50 * 1024 * 1024)),
            max_active_scans_per_key=int(data.get("max_active_scans_per_key", 3)),
            audit_log_path=Path(audit) if audit else None,
            worker_concurrency=int(data.get("worker_concurrency", 1)),
            poll_interval_seconds=float(data.get("poll_interval_seconds", 0.5)),
            heartbeat_interval_seconds=float(
                data.get("heartbeat_interval_seconds", 15.0)),
            heartbeat_timeout_seconds=float(
                data.get("heartbeat_timeout_seconds", 60.0)),
            reclaim_interval_seconds=float(data.get("reclaim_interval_seconds", 30.0)),
            max_attempts=int(data.get("max_attempts", 2)),
        )

    @classmethod
    def from_yaml(cls, path) -> "ServiceConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)
