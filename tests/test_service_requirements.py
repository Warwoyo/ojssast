"""Tests covering service/core acceptance criteria from the spec.

These tests validate requirements that are not already covered by other test
modules: worker scan_options handling, config payload apache key routing,
safe extraction, local scan, scan-bundle CLI, and ruleset loader stability.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ojs_sast.detectors.config_scanner import ConfigScanner
from ojs_sast.models import Severity
from ojs_sast.orchestrator import Orchestrator
from ojs_sast.ruleset.loader import load_ruleset
from ojs_sast.service.extract import UnsafeArchiveError, safe_extract_archive

FIXTURES = Path(__file__).parent / "fixtures"


# ── safe extraction ──────────────────────────────────────────────────────── #

def test_safe_extract_rejects_path_traversal(tmp_path):
    """safe_extract_archive must reject ``../`` path traversal members."""
    bad = tmp_path / "evil.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        data = b"payload"
        info = tarfile.TarInfo("../../outside.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(bad, tmp_path / "out")
    assert not (tmp_path / "outside.txt").exists()


# ── config payload apache routing ───────────────────────────────────────── #

def test_config_payload_ignores_apache_for_nginx_checks(ruleset):
    """Keys prefixed ``apache:`` must not trigger nginx_* rules."""
    nginx_text_with_issues = "# empty apache config\n"  # no nginx directives → nginx checks fire
    # But the key is "apache:..." so it must NOT be routed to nginx checks.
    findings = ConfigScanner(ruleset).scan_payload({
        "apache:/etc/apache2/sites-enabled/ojs.conf": nginx_text_with_issues,
    })
    # No nginx findings — the apache key was ignored.
    nginx_findings = [f for f in findings if f.module == "config"
                      and f.file_path.startswith("apache:")]
    assert not nginx_findings, (
        "apache: keys must not be processed by nginx checks"
    )


def test_config_payload_routes_nginx_prefix_correctly(ruleset):
    """Only ``nginx:*`` keys are routed to nginx checks."""
    nginx_insecure = (FIXTURES / "config" / "nginx_insecure.conf").read_text(encoding="utf-8")
    findings_nginx = ConfigScanner(ruleset).scan_payload({
        "nginx:/etc/nginx/sites-enabled/ojs": nginx_insecure,
    })
    findings_apache = ConfigScanner(ruleset).scan_payload({
        "apache:/etc/apache2/sites-enabled/ojs.conf": nginx_insecure,
    })
    # nginx: key produces nginx findings; apache: key must not.
    assert findings_nginx, "nginx: key should produce config findings"
    assert not findings_apache, "apache: key should produce no findings"


# ── worker scan_options ──────────────────────────────────────────────────── #

def test_worker_uses_scan_options_min_severity(tmp_path, ruleset):
    """Worker must pass min_severity from scan_options to the Orchestrator."""
    pytest.importorskip("fastapi")
    from ojs_sast.service.config import ServiceConfig
    from ojs_sast.service.queue import JobQueue
    from ojs_sast.service.storage import Storage
    from ojs_sast.service.worker import Worker

    storage = Storage(tmp_path / "data")
    queue = JobQueue()
    config = ServiceConfig(data_dir=tmp_path / "data")
    worker = Worker(storage, queue, config, ruleset=ruleset)

    # Create a job with min_severity=CRITICAL in scan_options.
    scan_id = "test-sev-001"
    job_dir = storage.create_job(scan_id, "test-key")

    # Build a minimal source archive.
    source_path = job_dir / "source.tar.gz"
    with tarfile.open(source_path, "w:gz") as tar:
        data = b"<?php echo 1;\n"
        info = tarfile.TarInfo("source/index.php")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    # meta.json with CRITICAL min_severity.
    meta = {
        "ojs_version": "3.3.0-13",
        "ojs_detected": False,
        "detection_markers": [],
        "source_label": "test",
        "scan_options": {
            "categories": ["source_code"],
            "min_severity": "CRITICAL",
            "formats": ["json"],
        },
        "source_archive": {"top_level_dir": "source", "sha256": None, "bytes": 0},
        "config_files": {},
        "upload_manifest": None,
    }
    (job_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    storage.update(scan_id, status="queued")

    worker.process_job(scan_id)
    row = storage.get(scan_id)
    assert row["status"] == "done", row.get("error")

    result = json.loads((job_dir / "result.json").read_text())
    # With min_severity=CRITICAL, all findings must be CRITICAL.
    for f in result.get("findings", []):
        assert f["severity"] == "CRITICAL", (
            f"Finding {f['rule_id']} has severity {f['severity']}, expected CRITICAL"
        )


def test_worker_uses_scan_options_categories(tmp_path, ruleset):
    """Worker must restrict scan to categories listed in scan_options."""
    pytest.importorskip("fastapi")
    from ojs_sast.service.config import ServiceConfig
    from ojs_sast.service.queue import JobQueue
    from ojs_sast.service.storage import Storage
    from ojs_sast.service.worker import Worker

    storage = Storage(tmp_path / "data")
    queue = JobQueue()
    config = ServiceConfig(data_dir=tmp_path / "data")
    worker = Worker(storage, queue, config, ruleset=ruleset)

    scan_id = "test-cat-001"
    job_dir = storage.create_job(scan_id, "test-key")

    source_path = job_dir / "source.tar.gz"
    with tarfile.open(source_path, "w:gz") as tar:
        data = b"<?php echo 1;\n"
        info = tarfile.TarInfo("source/index.php")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    # meta.json with only config category — source_code must not run.
    insecure_cfg = (FIXTURES / "config" / "insecure_config.inc.php").read_text(encoding="utf-8")
    meta = {
        "ojs_version": "3.3.0-13",
        "ojs_detected": False,
        "detection_markers": [],
        "source_label": "test",
        "scan_options": {
            "categories": ["config"],
            "min_severity": "INFO",
            "formats": ["json"],
        },
        "source_archive": {"top_level_dir": "source", "sha256": None, "bytes": 0},
        "config_files": {"config.inc.php": insecure_cfg},
        "upload_manifest": None,
    }
    (job_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    storage.update(scan_id, status="queued")

    worker.process_job(scan_id)
    row = storage.get(scan_id)
    assert row["status"] == "done", row.get("error")

    result = json.loads((job_dir / "result.json").read_text())
    modules_found = {f["module"] for f in result.get("findings", [])}
    assert "source_code" not in modules_found, (
        "source_code module must not run when categories=['config']"
    )
    assert "config" in modules_found, "config module should produce findings"


def test_worker_rejects_invalid_min_severity(tmp_path, ruleset):
    """Worker must set status=error when min_severity is not a valid Severity."""
    pytest.importorskip("fastapi")
    from ojs_sast.service.config import ServiceConfig
    from ojs_sast.service.queue import JobQueue
    from ojs_sast.service.storage import Storage
    from ojs_sast.service.worker import Worker

    storage = Storage(tmp_path / "data")
    queue = JobQueue()
    config = ServiceConfig(data_dir=tmp_path / "data")
    worker = Worker(storage, queue, config, ruleset=ruleset)

    scan_id = "test-badsev-001"
    job_dir = storage.create_job(scan_id, "test-key")

    source_path = job_dir / "source.tar.gz"
    with tarfile.open(source_path, "w:gz") as tar:
        data = b"<?php echo 1;\n"
        info = tarfile.TarInfo("source/index.php")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    meta = {
        "ojs_version": None,
        "ojs_detected": False,
        "detection_markers": [],
        "source_label": "test",
        "scan_options": {"min_severity": "INVALID_LEVEL"},
        "source_archive": {"top_level_dir": "source", "sha256": None, "bytes": 0},
        "config_files": {},
        "upload_manifest": None,
    }
    (job_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    storage.update(scan_id, status="queued")

    worker.process_job(scan_id)
    row = storage.get(scan_id)
    assert row["status"] == "error"
    assert "invalid_min_severity" in (row.get("error") or "").lower() or \
           "min_severity" in (row.get("error") or "")


# ── local scan still works ───────────────────────────────────────────────── #

def test_local_scan_still_works(mock_ojs, ruleset, tmp_path):
    """The local scan (ojs-sast scan) must still run and produce multi-module findings."""
    result = Orchestrator(mock_ojs, output_dir=tmp_path / "r",
                          ruleset=ruleset).run()
    modules = {f.module for f in result.findings}
    assert "source_code" in modules
    assert "config" in modules
    assert "upload_directory" in modules
    assert result.metadata["scan_mode"] == "local"
    assert result.metadata["ojs_version"] == "3.3.0-13"


# ── scan-bundle CLI still works ──────────────────────────────────────────── #

def test_scan_bundle_cli_still_works(mock_ojs, ruleset, tmp_path):
    """The ojs-sast scan-bundle command must accept a tar.gz + meta.json and scan."""
    from click.testing import CliRunner
    from ojs_sast.cli import cli

    # Build a minimal bundle inline (no agent module).
    import hashlib
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    source_archive = bundle_dir / "source.tar.gz"
    content = (FIXTURES / "vulnerable_php" / "xss_sample.php").read_bytes()
    with tarfile.open(source_archive, "w:gz") as tar:
        info = tarfile.TarInfo("source/xss_sample.php")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    digest = hashlib.sha256(source_archive.read_bytes()).hexdigest()
    meta = {
        "ojs_version": "3.3.0-13",
        "ojs_detected": False,
        "detection_markers": [],
        "source_label": "test",
        "scan_options": {"categories": ["source_code"], "min_severity": "INFO", "formats": ["json"]},
        "source_archive": {"top_level_dir": "source", "sha256": digest, "bytes": source_archive.stat().st_size},
        "config_files": {},
        "upload_manifest": None,
    }
    meta_path = bundle_dir / "meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    out_dir = tmp_path / "report"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "scan-bundle",
        "--source", str(source_archive),
        "--meta", str(meta_path),
        "--output-dir", str(out_dir),
        "--format", "json",
        "--category", "source_code",
    ])
    assert result.exit_code == 0, result.output
    # JSON report must be written.
    reports = list(out_dir.rglob("findings.json"))
    assert reports, "scan-bundle should produce a findings.json"


# ── ruleset loader unchanged ─────────────────────────────────────────────── #

def test_ruleset_loader_unchanged(ruleset):
    """Ruleset loader must load the full set of rules with valid IDs and modules."""
    assert len(ruleset) > 0, "ruleset must not be empty"
    modules = {r.module for r in ruleset.rules}
    assert "source_code" in modules
    assert "config" in modules
    assert "upload_directory" in modules

    # All rule IDs must be non-empty strings.
    for r in ruleset.rules:
        assert isinstance(r.id, str) and r.id, f"rule {r!r} has empty id"
        assert r.module in ("source_code", "config", "upload_directory"), (
            f"rule {r.id} has unknown module {r.module!r}"
        )

    # Reloading must produce the same count (deterministic).
    fresh = load_ruleset()
    assert len(fresh) == len(ruleset)
