"""End-to-end service tests (FastAPI TestClient).

Skipped automatically when the ``service`` extra (fastapi + python-multipart) is
not installed.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("multipart")  # python-multipart

from fastapi.testclient import TestClient  # noqa: E402

from ojs_sast.agent.bundle_builder import build_bundle  # noqa: E402
from ojs_sast.service.app import create_app  # noqa: E402
from ojs_sast.service.auth import hash_api_key  # noqa: E402
from ojs_sast.service.config import ServiceConfig  # noqa: E402

API_KEY = "test-api-key-123"


@pytest.fixture
def service(mock_ojs, ruleset, tmp_path):
    paths = build_bundle(mock_ojs, tmp_path / "bundle", ruleset=ruleset,
                         include_system_configs=False)
    config = ServiceConfig(
        data_dir=tmp_path / "svc",
        api_keys={hash_api_key(API_KEY): "agent-1"},
        audit_log_path=tmp_path / "audit.log",
    )
    app = create_app(config)
    with TestClient(app) as client:
        yield client, paths


def _submit(client, paths, key=API_KEY):
    with paths.source_archive.open("rb") as src, paths.meta_json.open("rb") as meta:
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


def test_health_requires_no_auth(service):
    client, _ = service
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_full_scan_lifecycle(service):
    client, paths = service
    resp = _submit(client, paths)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    assert resp.json()["status"] == "queued"

    final = _poll(client, scan_id)
    assert final["status"] == "done", final

    result = client.get(f"/result/{scan_id}", headers={"X-API-Key": API_KEY}).json()
    modules = {f["module"] for f in result["findings"]}
    assert {"source_code", "config", "upload_directory"} <= modules
    assert result["scan_metadata"]["scan_mode"] == "remote"

    for fmt in ("json", "html", "sarif"):
        rep = client.get(f"/report/{scan_id}/{fmt}", headers={"X-API-Key": API_KEY})
        assert rep.status_code == 200, fmt
        assert rep.content


def test_rejects_missing_and_bad_api_key(service):
    client, paths = service
    assert _submit(client, paths, key="wrong-key").status_code == 401
    # No header at all.
    with paths.source_archive.open("rb") as src, paths.meta_json.open("rb") as meta:
        resp = client.post(
            "/scan",
            files={"source_code": ("source.tar.gz", src, "application/gzip"),
                   "meta": ("meta.json", meta, "application/json")},
        )
    assert resp.status_code == 401


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
        {"source_archive": {"top_level_dir": "source"},
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
