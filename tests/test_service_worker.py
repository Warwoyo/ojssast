"""Tests for the service worker's scan_options handling.

Verifies that the worker reads ``scan_options.min_severity`` and
``scan_options.categories`` from ``meta.json`` and passes them to the
``Orchestrator``.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("multipart")

from fastapi.testclient import TestClient  # noqa: E402

from ojs_sast.detectors.config_scanner import extract_upload_dirs, parse_config  # noqa: E402
from ojs_sast.orchestrator import detect_ojs  # noqa: E402
from ojs_sast.service.app import create_app  # noqa: E402
from ojs_sast.service.auth import hash_api_key  # noqa: E402
from ojs_sast.service.config import ServiceConfig  # noqa: E402

API_KEY = "test-worker-key-456"

# ------------------------------------------------------------------ #
# Inline bundle builder
# ------------------------------------------------------------------ #
_INCLUDE_EXTENSIONS = {
    ".php", ".inc", ".tpl", ".smarty", ".js", ".json", ".xml", ".yml", ".yaml",
}
_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "cache", "tmp", "logs",
    "files", "uploads", "__pycache__",
}
_WHITELIST_FILES = {"version.xml"}
_HEAD_HEX_BYTES = 512


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sniff_mime(head: bytes) -> Optional[str]:
    stripped = head.lstrip()
    if stripped.startswith(b"<?php") or stripped.startswith(b"<?="):
        return "text/x-php"
    if head.startswith(b"%PDF"):
        return "application/pdf"
    return None


def _build_test_bundle(ojs_root: Path, work: Path,
                        *,
                        min_severity: str = "INFO",
                        categories: Optional[List[str]] = None) -> Tuple[Path, Path]:
    work.mkdir(parents=True, exist_ok=True)
    info = detect_ojs(ojs_root)
    ojs_resolved = ojs_root.resolve()

    config_files: Dict[str, str] = {}
    config_path = ojs_root / "config.inc.php"
    if config_path.is_file():
        config_files["config.inc.php"] = config_path.read_text(encoding="utf-8", errors="replace")
    sections = parse_config(config_files.get("config.inc.php", ""))

    files_dir, public_dir = extract_upload_dirs(sections) if sections else (None, None)
    upload_dirs: List[Path] = []
    for raw in (files_dir, public_dir):
        if not raw:
            continue
        p = Path(raw) if Path(raw).is_absolute() else ojs_root / raw
        if p.is_dir():
            upload_dirs.append(p)
    if not upload_dirs:
        fb = ojs_root / "public"
        if fb.is_dir():
            upload_dirs.append(fb)

    exclude_resolved = {p.resolve() for p in upload_dirs} | {(ojs_root / "public").resolve()}

    source_archive = work / "source.tar.gz"
    with tarfile.open(source_archive, "w:gz") as tar:
        for path in sorted(ojs_resolved.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(ojs_resolved)
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
            ti = tar.gettarinfo(str(path), arcname=arcname)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            with path.open("rb") as fh:
                tar.addfile(ti, fh)

    size = source_archive.stat().st_size
    sha256 = _sha256_file(source_archive)

    entries: List[Dict[str, Any]] = []
    total_size = 0
    for directory in upload_dirs:
        for fp in sorted(directory.rglob("*")):
            if fp.is_symlink() or not fp.is_file():
                continue
            r = str(fp.relative_to(directory))
            try:
                stat = fp.stat()
                with fp.open("rb") as fh:
                    head = fh.read(_HEAD_HEX_BYTES)
            except OSError:
                continue
            entries.append({
                "path": r, "filename": fp.name, "extension": fp.suffix.lower(),
                "size_bytes": stat.st_size, "head_hex": head.hex(),
                "detected_mime": _sniff_mime(head),
                "null_byte_in_name": False, "is_hidden": fp.name.startswith("."),
            })
            total_size += stat.st_size

    meta: Dict[str, Any] = {
        "schema_version": 1,
        "agent_version": "1.0.0-test",
        "agent_id": "test-worker",
        "agent_hostname": "test-host",
        "bundle_id": "test-worker-bundle",
        "created_at": "2026-01-01T00:00:00Z",
        "ojs_version": info.version,
        "ojs_detected": info.is_ojs,
        "detection_markers": info.markers,
        "source_label": ojs_root.name,
        "scan_options": {
            "categories": categories or ["source_code", "config", "upload_directory"],
            "min_severity": min_severity,
            "formats": ["json"],
        },
        "source_archive": {
            "filename": "source.tar.gz", "sha256": sha256,
            "bytes": size, "top_level_dir": "source",
        },
        "config_files": config_files,
        "upload_manifest": {
            "generated_at": "2026-01-01T00:00:00Z",
            "upload_roots": [str(d) for d in upload_dirs],
            "total_files": len(entries),
            "total_size_bytes": total_size,
            "entries": entries,
        },
    }
    meta_path = work / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return source_archive, meta_path


def _make_service(tmp_path):
    config = ServiceConfig(
        data_dir=tmp_path / "svc",
        api_keys={hash_api_key(API_KEY): "agent-worker-test"},
        audit_log_path=tmp_path / "audit.log",
    )
    app = create_app(config)
    return app


def _submit(client, source_path, meta_path, key=API_KEY):
    with source_path.open("rb") as src, meta_path.open("rb") as meta:
        return client.post(
            "/scan", headers={"X-API-Key": key},
            files={"source_code": ("source.tar.gz", src, "application/gzip"),
                   "meta": ("meta.json", meta, "application/json")},
        )


def _poll(client, scan_id, key=API_KEY, tries=200):
    for _ in range(tries):
        st = client.get(f"/status/{scan_id}", headers={"X-API-Key": key}).json()
        if st["status"] in ("done", "error"):
            return st
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not finish in time")


# ------------------------------------------------------------------ #
# Tests
# ------------------------------------------------------------------ #
def test_worker_uses_scan_options_min_severity(mock_ojs, tmp_path):
    """Findings below min_severity from meta.json must be filtered out."""
    # First: scan with INFO -> get all findings.
    source_info, meta_info = _build_test_bundle(
        mock_ojs, tmp_path / "info", min_severity="INFO")
    app = _make_service(tmp_path / "svc_info")
    with TestClient(app) as client:
        resp = _submit(client, source_info, meta_info)
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]
        final = _poll(client, scan_id)
        assert final["status"] == "done"
        result_info = client.get(
            f"/result/{scan_id}", headers={"X-API-Key": API_KEY}).json()
    total_info = result_info["summary"]["total_findings"]

    # Second: scan with CRITICAL -> only CRITICAL findings.
    source_crit, meta_crit = _build_test_bundle(
        mock_ojs, tmp_path / "crit", min_severity="CRITICAL")
    app2 = _make_service(tmp_path / "svc_crit")
    with TestClient(app2) as client:
        resp = _submit(client, source_crit, meta_crit)
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]
        final = _poll(client, scan_id)
        assert final["status"] == "done"
        result_crit = client.get(
            f"/result/{scan_id}", headers={"X-API-Key": API_KEY}).json()
    total_crit = result_crit["summary"]["total_findings"]

    # With min_severity=CRITICAL, we should get fewer findings.
    assert total_crit <= total_info
    # All returned findings must be CRITICAL.
    for f in result_crit["findings"]:
        assert f["severity"] == "CRITICAL"


def test_worker_uses_scan_options_categories(mock_ojs, tmp_path):
    """Only the requested categories from scan_options should be scanned."""
    source, meta_path = _build_test_bundle(
        mock_ojs, tmp_path / "cat", categories=["source_code"])
    app = _make_service(tmp_path / "svc_cat")
    with TestClient(app) as client:
        resp = _submit(client, source, meta_path)
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]
        final = _poll(client, scan_id)
        assert final["status"] == "done"
        result = client.get(
            f"/result/{scan_id}", headers={"X-API-Key": API_KEY}).json()

    modules = {f["module"] for f in result["findings"]}
    # Only source_code should be present.
    assert modules <= {"source_code"}, f"unexpected modules: {modules}"


def test_config_payload_ignores_apache_for_nginx_checks(ruleset):
    """Apache config entries must NOT be routed through nginx checks."""
    from ojs_sast.detectors.config_scanner import ConfigScanner

    apache_conf = """
    <VirtualHost *:80>
        ServerName ojs.example.com
        DocumentRoot /var/www/ojs
    </VirtualHost>
    """
    config_files = {
        "apache:/etc/apache2/sites-enabled/ojs.conf": apache_conf,
    }
    scanner = ConfigScanner(ruleset)
    findings = scanner.scan_payload(config_files)
    # No nginx findings should fire from Apache config.
    nginx_findings = [f for f in findings if "nginx" in f.rule_id.lower()
                      or "nginx" in (f.detail or "").lower()]
    assert not nginx_findings, f"Apache config triggered nginx findings: {nginx_findings}"
