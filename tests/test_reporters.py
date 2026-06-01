"""Tests for the JSON / HTML / SARIF reporters."""

import json

from ojs_sast.models import Finding, ScanResult, Severity
from ojs_sast.reporters.html_reporter import render_html, write_html_report
from ojs_sast.reporters.json_reporter import render_json, write_json_report
from ojs_sast.reporters.sarif_reporter import render_sarif, write_sarif_report


def _sample_result():
    findings = [
        Finding(rule_id="RULE-SRC-005", module="source_code", severity=Severity.CRITICAL,
                file_path="classes/Dao.php", line=42, title="SQL injection",
                detail="Tainted data reaches DB::raw.", cwe="CWE-89", owasp="A03:2021",
                cvss_score=9.8, cve_references=["CVE-2025-67889"],
                code_snippet="DB::raw($sql);", confidence="high"),
        Finding(rule_id="OJS-CFG-SEC-001", module="config", severity=Severity.CRITICAL,
                file_path="config.inc.php", title="Weak salt", detail="salt is 'changeme'",
                cwe="CWE-330"),
        Finding(rule_id="RULE-UPLOAD-001", module="upload_directory", severity=Severity.CRITICAL,
                file_path="shell.php", title="Dangerous extension", detail="PHP in uploads",
                layer="dangerous_extension", actual_mime="text/x-php", declared_extension=".php"),
    ]
    meta = {
        "tool": "ojs-sast", "version": "1.0.0", "ojs_path": "/srv/ojs",
        "ojs_version": "3.3.0-13", "scan_timestamp": "2026-06-01T00:00:00+00:00",
        "modules_run": ["source_code", "config", "upload_directory"],
        "rules_loaded": 33, "files_scanned": {"source_code": 10}, "duration_seconds": 0.5,
    }
    return ScanResult(metadata=meta, findings=findings)


def test_json_structure():
    data = json.loads(render_json(_sample_result()))
    assert data["scan_metadata"]["tool"] == "ojs-sast"
    assert data["summary"]["total_findings"] == 3
    assert data["summary"]["by_severity"]["CRITICAL"] == 3
    assert data["summary"]["by_module"]["config"] == 1
    assert len(data["findings"]) == 3
    f = data["findings"][0]
    for key in ("finding_id", "rule_id", "module", "severity", "file_path", "remediation"):
        assert key in f


def test_json_written_to_disk(tmp_path):
    path = write_json_report(_sample_result(), tmp_path)
    assert path.exists()
    json.loads(path.read_text())


def test_sarif_structure():
    data = json.loads(render_sarif(_sample_result()))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "ojs-sast"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "RULE-SRC-005" in rule_ids
    assert len(run["results"]) == 3
    # CRITICAL -> error level; security-severity present.
    assert run["results"][0]["level"] == "error"
    sqli_rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "RULE-SRC-005")
    assert sqli_rule["properties"]["security-severity"] == "9.8"
    assert "external/cwe/cwe-89" in sqli_rule["properties"]["tags"]


def test_sarif_location_region():
    data = json.loads(render_sarif(_sample_result()))
    results = {r["ruleId"]: r for r in data["runs"][0]["results"]}
    # source finding has a line region; upload finding has none.
    src = results["RULE-SRC-005"]["locations"][0]["physicalLocation"]
    assert src["region"]["startLine"] == 42
    up = results["RULE-UPLOAD-001"]["locations"][0]["physicalLocation"]
    assert "region" not in up


def test_html_contains_findings(tmp_path):
    html = render_html(_sample_result())
    assert "ojs-sast security report" in html
    assert "SQL injection" in html
    assert "CRITICAL" in html
    assert "DB::raw($sql);" in html
    path = write_html_report(_sample_result(), tmp_path)
    assert path.exists() and path.stat().st_size > 0


def test_html_escapes_snippet():
    f = Finding(rule_id="X", module="source_code", severity=Severity.HIGH,
                file_path="a.php", title="t", code_snippet="<script>alert(1)</script>")
    html = render_html(ScanResult(metadata={"version": "1.0.0", "ojs_path": "p",
                                            "ojs_version": "3", "scan_timestamp": "t",
                                            "modules_run": []}, findings=[f]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
