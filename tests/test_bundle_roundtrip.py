"""Integration tests for the agent bundle -> run_bundle pipeline.

Builds a real bundle from the ``mock_ojs`` fixture, extracts it safely, and runs
``Orchestrator.run_bundle``; also asserts parity with the local scan.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from ojs_sast.agent.bundle_builder import build_bundle
from ojs_sast.models.bundle import ScanBundle, resolve_source_root
from ojs_sast.orchestrator import Orchestrator
from ojs_sast.service.extract import safe_extract_archive


def _build_and_load(ojs_root, work: Path, ruleset):
    work.mkdir(parents=True, exist_ok=True)
    paths = build_bundle(ojs_root, work / "bundle", ruleset=ruleset,
                         include_system_configs=False)
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


def test_archive_excludes_uploads(mock_ojs, ruleset, tmp_path):
    _, _, paths = _build_and_load(mock_ojs, tmp_path / "w", ruleset)
    with tarfile.open(paths.source_archive) as tar:
        names = tar.getnames()
    # The webshell in files/ must NOT be shipped; the template source must be.
    assert not any("/files/" in n or n.endswith("/shell.php") for n in names)
    assert any(n.endswith("submissions.tpl") for n in names)


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
