"""Integration tests for the run_bundle pipeline.

Builds a test bundle inline (without the agent package), extracts it safely,
and runs ``Orchestrator.run_bundle``; also asserts parity with the local scan.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ojs_sast.detectors.config_scanner import extract_upload_dirs, parse_config
from ojs_sast.models.bundle import ScanBundle, resolve_source_root
from ojs_sast.orchestrator import Orchestrator, detect_ojs
from ojs_sast.service.extract import safe_extract_archive


# ------------------------------------------------------------------ #
# Inline bundle builder (replaces ojs_sast.agent.bundle_builder)
# ------------------------------------------------------------------ #
_INCLUDE_EXTENSIONS = {
    ".php", ".inc", ".tpl", ".smarty", ".js", ".json", ".xml", ".yml", ".yaml",
}
_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "bower_components", "vendor",
    "cache", "tmp", "logs", "files", "uploads", "__pycache__",
}
_WHITELIST_FILES = {"version.xml"}
_HEAD_HEX_BYTES = 512


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_source_archive(ojs_root: Path, out_path: Path,
                           exclude_resolved: Set[Path]) -> Tuple[str, int]:
    """Minimal source archive builder for tests."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ojs_root = ojs_root.resolve()
    with tarfile.open(out_path, "w:gz") as tar:
        for path in sorted(ojs_root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(ojs_root)
            if any(part in _EXCLUDE_DIRS for part in rel.parts):
                continue
            rp = path.resolve()
            if any(rp == ex or ex in rp.parents for ex in exclude_resolved):
                continue
            if path.suffix.lower() not in _INCLUDE_EXTENSIONS and path.name not in _WHITELIST_FILES:
                continue
            if path.stat().st_size > 10 * 1024 * 1024:
                continue
            with path.open("rb") as fh:
                if b"\x00" in fh.read(4096):
                    continue
            arcname = "source/" + str(rel).replace("\\", "/")
            info = tar.gettarinfo(str(path), arcname=arcname)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as fh:
                tar.addfile(info, fh)
    size = out_path.stat().st_size
    sha256 = _sha256_file(out_path)
    return sha256, size


def _build_upload_manifest(upload_dirs: List[Path]) -> Dict[str, Any]:
    """Build a raw-evidence upload manifest (no ruleset dependency)."""
    entries: List[Dict[str, Any]] = []
    total_size = 0
    roots: List[str] = []
    for directory in upload_dirs:
        if not directory.is_dir():
            continue
        roots.append(str(directory))
        for path in sorted(directory.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            rel = str(path.relative_to(directory))
            name = path.name
            ext = path.suffix.lower()
            try:
                stat = path.stat()
                with path.open("rb") as fh:
                    head = fh.read(_HEAD_HEX_BYTES)
            except OSError:
                continue
            entries.append({
                "path": rel,
                "filename": name,
                "extension": ext,
                "size_bytes": stat.st_size,
                "mtime_unix": stat.st_mtime,
                "sha256": None,
                "head_hex": head.hex(),
                "detected_mime": _sniff_mime(head),
                "null_byte_in_name": "\x00" in name,
                "is_hidden": name.startswith("."),
            })
            total_size += stat.st_size
    return {
        "generated_at": "2026-01-01T00:00:00Z",
        "upload_roots": roots,
        "total_files": len(entries),
        "total_size_bytes": total_size,
        "entries": entries,
    }


def _sniff_mime(head: bytes) -> Optional[str]:
    stripped = head.lstrip()
    if stripped.startswith(b"<?php") or stripped.startswith(b"<?="):
        return "text/x-php"
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    return None


def _build_test_bundle(ojs_root: Path, work: Path) -> Tuple[ScanBundle, Dict[str, Any], Path, Path]:
    """Build source.tar.gz + meta.json from a mock OJS tree (no agent)."""
    work.mkdir(parents=True, exist_ok=True)
    info = detect_ojs(ojs_root)

    # Read config
    config_files: Dict[str, str] = {}
    config_path = ojs_root / "config.inc.php"
    if config_path.is_file():
        config_files["config.inc.php"] = config_path.read_text(encoding="utf-8", errors="replace")
    sections = parse_config(config_files["config.inc.php"]) if "config.inc.php" in config_files else {}

    # Resolve upload dirs
    files_dir, public_dir = extract_upload_dirs(sections) if sections else (None, None)
    upload_dirs: List[Path] = []
    for raw in (files_dir, public_dir):
        if not raw:
            continue
        p = Path(raw) if Path(raw).is_absolute() else ojs_root / raw
        if p.is_dir():
            upload_dirs.append(p)
    if not upload_dirs:
        fallback = ojs_root / "public"
        if fallback.is_dir():
            upload_dirs.append(fallback)

    # Build source archive excluding upload dirs
    source_archive = work / "source.tar.gz"
    exclude_resolved = {p.resolve() for p in upload_dirs} | {(ojs_root / "public").resolve()}
    sha256, size = _build_source_archive(ojs_root, source_archive, exclude_resolved)

    # Build manifest
    manifest = _build_upload_manifest(upload_dirs)

    meta: Dict[str, Any] = {
        "schema_version": 1,
        "agent_version": "1.0.0-test",
        "agent_id": "test-inline",
        "agent_hostname": "test-host",
        "bundle_id": "test-bundle-id",
        "created_at": "2026-01-01T00:00:00Z",
        "ojs_version": info.version,
        "ojs_detected": info.is_ojs,
        "detection_markers": info.markers,
        "source_label": ojs_root.name,
        "scan_options": {
            "categories": ["source_code", "config", "upload_directory"],
            "min_severity": "INFO",
            "formats": ["json", "html", "sarif"],
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

    meta_path = work / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Extract and build bundle
    extracted = work / "extracted"
    safe_extract_archive(source_archive, extracted)
    bundle = ScanBundle.from_meta(meta, resolve_source_root(extracted, meta))
    return bundle, meta, source_archive, meta_path


# ------------------------------------------------------------------ #
# Tests
# ------------------------------------------------------------------ #
def test_run_bundle_multi_module(mock_ojs, ruleset, tmp_path):
    bundle, meta, _, _ = _build_test_bundle(mock_ojs, tmp_path / "w")
    result = Orchestrator(bundle.source_root, ruleset=ruleset).run_bundle(bundle)

    modules = {f.module for f in result.findings}
    assert {"source_code", "config", "upload_directory"} <= modules
    assert result.metadata["scan_mode"] == "remote"
    assert result.metadata["ojs_version"] == "3.3.0-13"
    assert result.metadata["ojs_detected"] is True
    assert result.metadata["upload_manifest_entries"] == meta["upload_manifest"]["total_files"]


def test_archive_excludes_uploads(mock_ojs, ruleset, tmp_path):
    _, _, source_archive, _ = _build_test_bundle(mock_ojs, tmp_path / "w")
    with tarfile.open(source_archive) as tar:
        names = tar.getnames()
    # The webshell in files/ must NOT be shipped; the template source must be.
    assert not any("/files/" in n or n.endswith("/shell.php") for n in names)
    assert any(n.endswith("submissions.tpl") for n in names)


def test_bundle_parity_with_local(mock_ojs, ruleset, tmp_path):
    local = Orchestrator(mock_ojs, ruleset=ruleset).run_local()
    bundle, _, _, _ = _build_test_bundle(mock_ojs, tmp_path / "w")
    remote = Orchestrator(bundle.source_root, ruleset=ruleset).run_bundle(bundle)

    def source(findings):
        return {(f.rule_id, f.file_path) for f in findings if f.module == "source_code"}

    assert source(local.findings) == source(remote.findings)

    # Config parity on INI checks (exclude nginx: file paths differ and the
    # local scan may also pick up system nginx configs).
    nginx_ids = {r.id for r in ruleset.by_module("config")
                 if str(r.params.get("check", "")).startswith("nginx_")}
    local_cfg = {f.rule_id for f in local.findings
                 if f.module == "config" and f.rule_id not in nginx_ids}
    remote_cfg = {f.rule_id for f in remote.findings
                  if f.module == "config" and f.rule_id not in nginx_ids}
    assert local_cfg == remote_cfg


def test_local_mode_scan_mode_metadata(mock_ojs, ruleset):
    """run_local adds scan_mode=local without changing the existing 13 keys."""
    result = Orchestrator(mock_ojs, ruleset=ruleset).run_local()
    assert result.metadata["scan_mode"] == "local"
    for key in ("tool", "version", "ojs_path", "ojs_version", "ojs_detected",
                "detection_markers", "scan_timestamp", "modules_run", "rules_loaded",
                "files_scanned", "min_severity", "duration_seconds",
                "findings_before_dedup", "findings_after_dedup"):
        assert key in result.metadata
