import importlib.util
import json
from pathlib import Path


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_sast.py"
_SPEC = importlib.util.spec_from_file_location("evaluate_sast", _SCRIPT)
evaluate_sast = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(evaluate_sast)


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _scan_payload():
    return {
        "scanner_version": "test",
        "findings": [
            {
                "rule_id": "OJS-CFG-SEC-001",
                "name": "force_ssl disabled",
                "severity": "HIGH",
                "category": "config",
                "file_path": "config.inc.php",
                "line_start": 10,
                "ground_truth": True,
                "evaluation_scope": "ground_truth",
            },
            {
                "rule_id": "OJS-CFG-NGX-001",
                "name": "Nginx upload PHP execution not blocked",
                "severity": "CRITICAL",
                "category": "config",
                "file_path": "nginx.conf",
                "line_start": 1,
                "ground_truth": False,
                "evaluation_scope": "extension",
            },
            {
                "rule_id": "RULE-SRC-010",
                "name": "Generic source heuristic",
                "severity": "MEDIUM",
                "category": "source_code",
                "file_path": "classes/Foo.php",
                "line_start": 25,
                "ground_truth": False,
                "evaluation_scope": "generic",
            },
            {
                "rule_id": "RULE-UPLOAD-001",
                "name": "Uploaded PHP file",
                "severity": "CRITICAL",
                "category": "uploaded_file",
                "file_path": "files/shell.php",
                "line_start": 1,
                "ground_truth": False,
                "evaluation_scope": "upload",
            },
        ],
    }


def test_strict_gt_scope_does_not_count_extension_generic_or_upload_as_false_positives(tmp_path):
    scan = _write_json(tmp_path / "scan.json", _scan_payload())
    gt_config = _write_json(tmp_path / "gt_config.json", {"rules": ["OJS-CFG-SEC-001", "OJS-CFG-SEC-002"]})
    gt_cve = _write_json(tmp_path / "gt_cve.json", [])

    result = evaluate_sast.evaluate_scan_results(
        [scan],
        gt_config,
        gt_cve,
        ruleset_dir=None,
        scope="strict-gt",
    )

    assert result["scope"] == "strict-gt"
    assert result["total_gt"] == 2
    assert result["predicted"] == 1
    assert result["tp"] == 1
    assert result["fp"] == 0
    assert result["fn"] == 1
    assert result["false_positives"] == []
    assert result["false_negatives"] == ["OJS-CFG-SEC-002"]


def test_all_reported_counts_non_upload_findings_against_ground_truth(tmp_path):
    scan = _write_json(tmp_path / "scan.json", _scan_payload())
    gt_config = _write_json(tmp_path / "gt_config.json", {"rules": ["OJS-CFG-SEC-001"]})
    gt_cve = _write_json(tmp_path / "gt_cve.json", [])

    result = evaluate_sast.evaluate_scan_results(
        [scan],
        gt_config,
        gt_cve,
        ruleset_dir=None,
        scope="all-reported",
    )

    assert result["predicted"] == 3
    assert result["tp"] == 1
    assert result["fp"] == 2
    assert "RULE-UPLOAD-001" not in result["false_positives"]
    assert result["false_positives"] == ["OJS-CFG-NGX-001", "RULE-SRC-010"]


def test_extension_aware_reports_strict_metrics_with_extension_and_generic_lists(tmp_path):
    scan = _write_json(tmp_path / "scan.json", _scan_payload())
    gt_config = _write_json(tmp_path / "gt_config.json", {"rules": ["OJS-CFG-SEC-001"]})
    gt_cve = _write_json(tmp_path / "gt_cve.json", [])

    result = evaluate_sast.evaluate_scan_results(
        [scan],
        gt_config,
        gt_cve,
        ruleset_dir=None,
        scope="extension-aware",
    )

    assert result["predicted"] == 1
    assert result["tp"] == 1
    assert result["fp"] == 0
    assert [finding["rule_id"] for finding in result["extension_findings"]] == ["OJS-CFG-NGX-001"]
    assert [finding["rule_id"] for finding in result["generic_findings"]] == ["RULE-SRC-010"]


def test_ground_truth_cve_ids_are_mapped_to_ruleset_rule_ids(tmp_path):
    scan = _write_json(
        tmp_path / "scan.json",
        {
            "findings": [
                {
                    "rule_id": "CVE-SRC-001",
                    "ground_truth": True,
                    "evaluation_scope": "ground_truth",
                }
            ]
        },
    )
    gt_config = _write_json(tmp_path / "gt_config.json", [])
    gt_cve = _write_json(tmp_path / "gt_cve.json", {"cves": ["CVE-2025-67889"]})

    result = evaluate_sast.evaluate_scan_results(
        [scan],
        gt_config,
        gt_cve,
        ruleset_dir=None,
        scope="strict-gt",
    )

    assert result["total_gt"] == 1
    assert result["tp"] == 1
    assert result["false_negatives"] == []
