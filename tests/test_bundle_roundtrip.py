"""Integration tests for the bundle -> run_bundle pipeline.

Builds a real bundle from the ``mock_ojs`` fixture without using the agent
module, safely extracts it, and runs ``Orchestrator.run_bundle``; also asserts
parity with the local scan.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from ojs_sast.models.bundle import ScanBundle, resolve_source_root
from ojs_sast.orchestrator import Orchestrator
from ojs_sast.service.extract import safe_extract_archive

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class _BundlePaths:
    source_archive: Path
    meta_json: Path
    meta: Dict[str, Any]


def _build_test_bundle(ojs_root: Path, out_dir: Path) -> _BundlePaths:
    """Build a minimal scan bundle from a mock OJS tree without the agent module.

    The source archive excludes the upload directories (files/ and public/).
    Each upload file is represented as a manifest entry with ``head_hex``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    upload_dirs = {ojs_root / "files", ojs_root / "public"}

    config_text = ""
    config_path = ojs_root / "config.inc.php"
    if config_path.exists():
        config_text = config_path.read_text(encoding="utf-8")

    # Build source.tar.gz (excluding upload dirs).
    source_archive = out_dir / "source.tar.gz"
    with tarfile.open(source_archive, "w:gz") as tar:
        for f in sorted(ojs_root.rglob("*")):
            if not f.is_file():
                continue
            if any(f.is_relative_to(ud) for ud in upload_dirs):
                continue
            rel = f.relative_to(ojs_root)
            info = tarfile.TarInfo(name=f"source/{rel}")
            data = f.read_bytes()
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    digest = hashlib.sha256(source_archive.read_bytes()).hexdigest()
    size = source_archive.stat().st_size

    # Build upload manifest entries from files dir using head_hex.
    entries = []
    for upload_dir in sorted(upload_dirs):
        if not upload_dir.is_dir():
            continue
        for f in sorted(upload_dir.rglob("*")):
            if not f.is_file():
                continue
            data = f.read_bytes()
            head = data[:512]

            detected_mime = "application/octet-stream"
            try:
                import magic as _magic  # python-magic is a core dep
                detected_mime = _magic.from_buffer(data[:65536], mime=True)
            except Exception:
                pass

            entries.append({
                "path": str(f.relative_to(ojs_root)),
                "filename": f.name,
                "extension": f.suffix.lower(),
                "size_bytes": len(data),
                "mtime_unix": int(f.stat().st_mtime),
                "sha256": hashlib.sha256(data).hexdigest(),
                "head_hex": head.hex(),
                "detected_mime": detected_mime,
                "null_byte_in_name": False,
                "is_hidden": f.name.startswith("."),
            })

    meta: Dict[str, Any] = {
        "schema_version": 1,
        "agent_version": "test-1.0",
        "agent_id": "test-agent",
        "agent_hostname": "test-host",
        "bundle_id": "test-bundle-001",
        "created_at": "2024-01-01T00:00:00+00:00",
        "ojs_version": "3.3.0-13",
        "ojs_detected": True,
        "detection_markers": ["config.inc.php", "lib/pkp"],
        "source_label": "test-ojs",
        "scan_options": {
            "categories": ["source_code", "config", "upload_directory"],
            "min_severity": "INFO",
            "formats": ["json", "html", "sarif"],
        },
        "source_archive": {
            "filename": "source.tar.gz",
            "sha256": digest,
            "bytes": size,
            "top_level_dir": "source",
        },
        "config_files": {"config.inc.php": config_text},
        "upload_manifest": {"total_files": len(entries), "entries": entries},
    }

    meta_path = out_dir / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return _BundlePaths(source_archive=source_archive, meta_json=meta_path, meta=meta)


def _build_and_load(ojs_root, work: Path, ruleset):
    work.mkdir(parents=True, exist_ok=True)
    paths = _build_test_bundle(Path(ojs_root), work / "bundle")
    meta = json.loads(paths.meta_json.read_text(encoding="utf-8"))
    extracted = work / "extracted"
    safe_extract_archive(paths.source_archive, extracted)
    bundle = ScanBundle.from_meta(meta, resolve_source_root(extracted, meta))
    return bundle, meta, paths


def test_run_bundle_multi_module(mock_ojs, ruleset, tmp_path):
    bundle, meta, _ = _build_and_load(mock_ojs, tmp_path / "w", ruleset)
    result = Orchestrator(bundle.source_root, ruleset=ruleset).run_bundle(bundle)

    modules = {f.module for f in result.findings}
    assert {"source_code", "config", "upload_directory"} <= modules
    assert result.metadata["scan_mode"] == "remote"
    assert result.metadata["ojs_version"] == "3.3.0-13"
    assert result.metadata["ojs_detected"] is True
    assert result.metadata["upload_manifest_entries"] == meta["upload_manifest"]["total_files"]


def test_bundle_parity_with_local(mock_ojs, ruleset, tmp_path):
    local = Orchestrator(mock_ojs, ruleset=ruleset).run_local()
    bundle, _, _ = _build_and_load(mock_ojs, tmp_path / "w", ruleset)
    remote = Orchestrator(bundle.source_root, ruleset=ruleset).run_bundle(bundle)

    def upload(findings):
        return {(f.rule_id, f.layer, f.severity.value, f.declared_extension)
                for f in findings if f.module == "upload_directory"}

    def source(findings):
        return {(f.rule_id, f.file_path) for f in findings if f.module == "source_code"}

    assert upload(local.findings) == upload(remote.findings)
    assert source(local.findings) == source(remote.findings)

    # Config parity on INI checks (exclude nginx IDs since local may pick up
    # system nginx configs; remote only has config.inc.php text).
    nginx_ids = {r.id for r in ruleset.by_module("config")
                 if str(r.params.get("check", "")).startswith("nginx_")}
    local_cfg = {f.rule_id for f in local.findings
                 if f.module == "config" and f.rule_id not in nginx_ids}
    remote_cfg = {f.rule_id for f in remote.findings
                  if f.module == "config" and f.rule_id not in nginx_ids}
    assert local_cfg == remote_cfg


def test_local_mode_scan_mode_metadata(mock_ojs, ruleset):
    """run_local adds scan_mode=local without changing the existing base keys."""
    result = Orchestrator(mock_ojs, ruleset=ruleset).run_local()
    assert result.metadata["scan_mode"] == "local"
    for key in ("tool", "version", "ojs_path", "ojs_version", "ojs_detected",
                "detection_markers", "scan_timestamp", "modules_run", "rules_loaded",
                "files_scanned", "min_severity", "duration_seconds",
                "findings_before_dedup", "findings_after_dedup"):
        assert key in result.metadata
