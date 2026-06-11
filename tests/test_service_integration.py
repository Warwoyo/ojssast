"""End-to-end service tests (FastAPI TestClient).

Skipped automatically when the ``service`` extra (fastapi + python-multipart) is
not installed.  Builds test bundles inline without the agent package.
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
pytest.importorskip("multipart")  # python-multipart

from fastapi.testclient import TestClient  # noqa: E402

from ojs_sast.service.app import create_app  # noqa: E402
from ojs_sast.service.auth import hash_api_key  # noqa: E402
from ojs_sast.service.config import ServiceConfig  # noqa: E402

API_KEY = "test-api-key-123"

# ------------------------------------------------------------------ #
# Inline bundle builder (no agent dependency)
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

def _build_minimal_bundle(tmp_path: Path):
    """Build a minimal source.tar.gz + meta.json without the agent module."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    source_archive = tmp_path / "source.tar.gz"
    content = b"<?php echo 'hello';\n"
    with tarfile.open(source_archive, "w:gz") as tar:
        info = tarfile.TarInfo("source/index.php")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    digest = hashlib.sha256(source_archive.read_bytes()).hexdigest()
    size = source_archive.stat().st_size

    meta = {
        "schema_version": 1,
        "agent_version": "test",
        "agent_id": "test-agent",
        "agent_hostname": "test-host",
        "bundle_id": "test-bundle",
        "created_at": "2024-01-01T00:00:00+00:00",
        "ojs_version": "3.3.0-13",
        "ojs_detected": True,
        "detection_markers": ["config.inc.php"],
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
        "config_files": {},
        "upload_manifest": {"total_files": 0, "entries": []},
    }
    meta_path = tmp_path / "meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    class _Paths:
        pass
    p = _Paths()
    p.source_archive = source_archive
    p.meta_json = meta_path
    p.meta = meta
    return p


@pytest.fixture
def service(tmp_path):
    paths = _build_minimal_bundle(tmp_path / "bundle")
    config = ServiceConfig(
        data_dir=tmp_path / "svc",
        api_keys={hash_api_key(API_KEY): "agent-1"},
        audit_log_path=tmp_path / "audit.log",
    )
    app = create_app(config)
    with TestClient(app) as client:
        yield client, paths


@pytest.fixture
def service_ip_restricted(tmp_path):
    """Service configured with IP allowlist that only allows 127.0.0.2."""
    paths = _build_minimal_bundle(tmp_path / "bundle")
    config = ServiceConfig(
        data_dir=tmp_path / "svc",
        api_keys={hash_api_key(API_KEY): "agent-1"},
        ip_allowlist=["127.0.0.2/32"],  # TestClient uses 127.0.0.1 → denied
        audit_log_path=tmp_path / "audit.log",
    )
    app = create_app(config)
    with TestClient(app) as client:
        yield client, paths


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


# ── required acceptance tests ────────────────────────────────────────────── #

def test_service_health(service):
    """GET /health requires no authentication and returns ok."""
    client, _ = service
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_service_rejects_invalid_api_key(service):
    """POST /scan with a wrong or missing API key must return 401."""
    client, paths = service
    assert _submit(client, paths.source_archive, paths.meta_json,
                   key="wrong-key").status_code == 401
    # No header at all.
    with paths.source_archive.open("rb") as src, paths.meta_json.open("rb") as meta:
        resp = client.post(
            "/scan",
            files={"source_code": ("source.tar.gz", src, "application/gzip"),
                   "meta": ("meta.json", meta, "application/json")},
        )
    assert resp.status_code == 401


def test_service_rejects_ip_not_allowlisted(service_ip_restricted):
    """POST /scan from a non-allowlisted IP must return 403."""
    client, paths = service_ip_restricted
    # TestClient's default client IP is 127.0.0.1 which is not in allowlist 127.0.0.2/32.
    resp = _submit(client, paths.source_archive, paths.meta_json)
    assert resp.status_code == 403


def test_service_rejects_bad_sha256(service, tmp_path):
    """POST /scan with a tampered archive (sha256 mismatch) must result in an error job."""
    client, paths = service

    # Tamper the meta so its sha256 doesn't match the real archive.
    meta = dict(paths.meta)
    meta["source_archive"] = dict(meta["source_archive"])
    meta["source_archive"]["sha256"] = "0" * 64  # wrong hash
    bad_meta = tmp_path / "bad_meta.json"
    bad_meta.write_text(json.dumps(meta), encoding="utf-8")

    with paths.source_archive.open("rb") as src, bad_meta.open("rb") as m:
        resp = client.post(
            "/scan", headers={"X-API-Key": API_KEY},
            files={"source_code": ("source.tar.gz", src, "application/gzip"),
                   "meta": ("meta.json", m, "application/json")},
        )
    assert resp.status_code == 400


def test_full_scan_lifecycle(service):
    client, paths = service
    resp = _submit(client, paths.source_archive, paths.meta_json)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    assert resp.json()["status"] == "queued"

    final = _poll(client, scan_id)
    assert final["status"] == "done", final

    result = client.get(f"/result/{scan_id}", headers={"X-API-Key": API_KEY}).json()
    assert result["scan_metadata"]["scan_mode"] == "remote"

    for fmt in ("json", "html", "sarif"):
        rep = client.get(f"/report/{scan_id}/{fmt}", headers={"X-API-Key": API_KEY})
        assert rep.status_code == 200, fmt
        assert rep.content


def test_status_unknown_scan(service):
    client, _ = service
    resp = client.get("/status/00000000-0000-0000-0000-000000000000",
                      headers={"X-API-Key": API_KEY})
    assert resp.status_code == 404


def test_result_before_finished_or_unknown(service):
    client, _ = service
    resp = client.get("/result/does-not-exist", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 404


def test_rejects_traversal_archive(service, tmp_path):
    client, _ = service
    bad = tmp_path / "evil.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        data = b"hacked"
        info = tarfile.TarInfo("../../escape.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    meta_bytes = json.dumps(
        {"source_archive": {"top_level_dir": "source", "sha256": None, "bytes": 0},
         "config_files": {}, "upload_manifest": []}).encode()

    with bad.open("rb") as src:
        resp = client.post(
            "/scan", headers={"X-API-Key": API_KEY},
            files={"source_code": ("source.tar.gz", src, "application/gzip"),
                   "meta": ("meta.json", io.BytesIO(meta_bytes), "application/json")},
        )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    final = _poll(client, scan_id)
    assert final["status"] == "error"
    assert not (Path("/tmp") / "escape.txt").exists()
