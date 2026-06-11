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
from ojs_sast.orchestrator import Orchestrator, detect_ojs
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
    paths = _build_test_bundle(Path(ojs_root), work / "bundle")
    meta = json.loads(paths.meta_json.read_text(encoding="utf-8"))
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


def test_bundle_parity_with_local(mock_ojs, ruleset, tmp_path):
    local = Orchestrator(mock_ojs, ruleset=ruleset).run_local()
    bundle, _, _, _ = _build_test_bundle(mock_ojs, tmp_path / "w")
    remote = Orchestrator(bundle.source_root, ruleset=ruleset).run_bundle(bundle)

    def source(findings):
        return {(f.rule_id, f.file_path) for f in findings if f.module == "source_code"}

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
