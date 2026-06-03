"""Integration tests for OJS detection and the scan orchestrator."""

import json

from ojs_sast.models import Severity
from ojs_sast.orchestrator import Orchestrator, detect_ojs


def test_detect_ojs(mock_ojs):
    info = detect_ojs(mock_ojs)
    assert info.is_ojs is True
    assert info.version == "3.3.0-13"
    assert info.config_path is not None
    assert "config.inc.php" in info.markers


def test_detect_non_ojs(tmp_path):
    info = detect_ojs(tmp_path)
    assert info.is_ojs is False


def test_full_scan_produces_multi_module_findings(mock_ojs, tmp_path):
    orch = Orchestrator(mock_ojs, output_dir=tmp_path / "report",
                        formats=["json", "html", "sarif"])
    result = orch.run()
    modules = {f.module for f in result.findings}
    assert "source_code" in modules
    assert "config" in modules
    assert "upload_directory" in modules

    written = orch.generate_reports(result)
    assert written["json"].exists()
    assert written["html"].exists()
    assert written["sarif"].exists()
    data = json.loads(written["json"].read_text())
    assert data["ojs_version"] == "3.3.0-13"
    assert len(data["findings"]) == len(result.findings)


def test_dedup_collapses_same_rule_file_line(mock_ojs, tmp_path):
    orch = Orchestrator(mock_ojs, output_dir=tmp_path / "r")
    result = orch.run()
    keys = [f.dedup_key for f in result.findings]
    assert len(keys) == len(set(keys))  # no duplicates remain


def test_min_severity_filter(mock_ojs, tmp_path):
    orch = Orchestrator(mock_ojs, output_dir=tmp_path / "r", min_severity=Severity.CRITICAL)
    result = orch.run()
    assert result.findings  # there are CRITICAL findings
    assert all(f.severity is Severity.CRITICAL for f in result.findings)


def test_skip_flags(mock_ojs, tmp_path):
    orch = Orchestrator(mock_ojs, output_dir=tmp_path / "r",
                        skip_source=True, skip_upload=True)
    result = orch.run()
    assert result.metadata["modules_run"] == ["config"]
    assert {f.module for f in result.findings} <= {"config"}


def test_category_filter(mock_ojs, tmp_path):
    orch = Orchestrator(mock_ojs, output_dir=tmp_path / "r", categories=["upload_directory"])
    result = orch.run()
    assert result.metadata["modules_run"] == ["upload_directory"]


def test_upload_dir_override(mock_ojs, tmp_path):
    from .conftest import FIXTURES
    orch = Orchestrator(mock_ojs, output_dir=tmp_path / "r",
                        categories=["upload_directory"],
                        upload_dir_override=FIXTURES / "upload" / "malicious")
    result = orch.run()
    assert any(f.layer == "webshell_signature" for f in result.findings)
