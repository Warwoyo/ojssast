"""Bundle builder (agent side).

Assembles a scan bundle from a local OJS install: a filtered ``source.tar.gz``
plus a ``meta.json`` carrying provenance, detected OJS version, the raw config
payload, and the upload manifest. The result is what the agent submits to the
service (or what ``ojs-sast scan-bundle`` consumes locally).
"""

from __future__ import annotations

import json
import logging
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..detectors.config_scanner import extract_upload_dirs, parse_config
from ..orchestrator import ALL_MODULES, detect_ojs
from ..ruleset.loader import Ruleset, load_ruleset
from . import AGENT_VERSION
from .config_collector import collect_configs
from .manifest import UploadManifestBuilder
from .snapshot import build_source_archive

logger = logging.getLogger("ojs_sast.agent.bundle")

SCHEMA_VERSION = 1


@dataclass
class BundlePaths:
    source_archive: Path
    meta_json: Path
    meta: Dict[str, Any]


def resolve_upload_dirs(
    ojs_root: Path,
    sections: Dict[str, Dict[str, str]],
    override: Optional[Sequence[Path]] = None,
) -> List[Path]:
    """Resolve upload directories from config (mirrors the orchestrator)."""
    if override:
        return [Path(p) for p in override if Path(p).is_dir()]
    dirs: List[Path] = []
    files_dir, public_dir = extract_upload_dirs(sections) if sections else (None, None)
    for raw in (files_dir, public_dir):
        if not raw:
            continue
        p = Path(raw)
        if not p.is_absolute():
            p = ojs_root / raw
        if p.is_dir():
            dirs.append(p)
    if not dirs:
        fallback = ojs_root / "public"
        if fallback.is_dir():
            dirs.append(fallback)
    return dirs


def build_bundle(
    ojs_root,
    out_dir,
    *,
    ruleset: Optional[Ruleset] = None,
    nginx_paths: Optional[Sequence[str]] = None,
    apache_paths: Optional[Sequence[str]] = None,
    upload_dirs: Optional[Sequence[Path]] = None,
    include_system_configs: bool = True,
    categories: Optional[Sequence[str]] = None,
    min_severity: str = "MEDIUM",
    formats: Optional[Sequence[str]] = None,
    source_label: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> BundlePaths:
    """Build ``source.tar.gz`` + ``meta.json`` under ``out_dir`` and return paths."""
    ojs_root = Path(ojs_root)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ruleset = ruleset or load_ruleset()

    info = detect_ojs(ojs_root)

    config_files = collect_configs(
        ojs_root, nginx_paths=nginx_paths, apache_paths=apache_paths,
        include_system_configs=include_system_configs,
    )
    sections = (parse_config(config_files["config.inc.php"])
                if "config.inc.php" in config_files else {})
    resolved_uploads = resolve_upload_dirs(ojs_root, sections, upload_dirs)

    source_archive = out_dir / "source.tar.gz"
    exclude_paths = set(resolved_uploads) | {ojs_root / "public"}
    sha256, size = build_source_archive(ojs_root, source_archive, exclude_paths=exclude_paths)

    manifest = UploadManifestBuilder(ruleset).build(resolved_uploads)

    meta: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "agent_version": AGENT_VERSION,
        "agent_id": agent_id,
        "agent_hostname": socket.gethostname(),
        "bundle_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "ojs_version": info.version,
        "ojs_detected": info.is_ojs,
        "detection_markers": info.markers,
        "source_label": source_label or ojs_root.name or "ojs",
        "scan_options": {
            "categories": list(categories) if categories else list(ALL_MODULES),
            "min_severity": min_severity,
            "formats": list(formats) if formats else ["json", "html", "sarif"],
        },
        "source_archive": {
            "filename": "source.tar.gz",
            "sha256": sha256,
            "bytes": size,
            "top_level_dir": "source",
        },
        "config_files": config_files,
        "upload_manifest": manifest,
    }

    meta_path = out_dir / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    logger.info("Bundle written: %s (%d source bytes, %d manifest entries)",
                out_dir, size, manifest["total_files"])
    return BundlePaths(source_archive=source_archive, meta_json=meta_path, meta=meta)
