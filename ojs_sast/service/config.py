"""Service configuration (``service.yml``).

Loaded with :func:`yaml.safe_load` into a plain dataclass (no pydantic), so it
works on the bare install. API keys are stored as **sha256 hashes only** — the
raw keys are never present in config or logs.
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
        )

    @classmethod
    def from_yaml(cls, path) -> "ServiceConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)
