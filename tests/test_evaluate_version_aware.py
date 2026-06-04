"""Tests for the version-aware strict-GT evaluator scope.

The denominator (expected applicable ground truth) must differ per OJS version,
and ground-truth findings that do not apply to the scanned version must be
counted as ``version_fp`` rather than true positives.
"""

import importlib.util
import json
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_sast.py"
_SPEC = importlib.util.spec_from_file_location("evaluate_sast", _SCRIPT)
evaluate_sast = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(evaluate_sast)


CONFIG_GT_IDS = (
    [f"OJS-CFG-GEN-{i:03d}" for i in range(1, 12)]
    + [f"OJS-CFG-SEC-{i:03d}" for i in range(1, 15)]
    + [f"OJS-CFG-DB-{i:03d}" for i in range(1, 4)]
    + [f"OJS-CFG-FILE-{i:03d}" for i in range(1, 5)]
    + ["OJS-CFG-EMAIL-001", "OJS-CFG-EMAIL-002", "OJS-CFG-CAP-001"]
    + [f"OJS-CFG-DBG-{i:03d}" for i in range(1, 5)]
)
CVE_IDS = [
    "CVE-2025-67889", "CVE-2025-67892", "CVE-2025-67890", "CVE-2025-67893",
    "CVE-2025-13469", "CVE-2023-47271", "CVE-2023-5903", "CVE-2023-5894",
    "CVE-2023-5626", "CVE-2022-26616", "CVE-2019-19909", "CVE-2018-12229",
]


def _write(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _gt_files(tmp_path):
    gt_config = _write(tmp_path / "gt_config.json", [{"check_id": c} for c in CONFIG_GT_IDS])
    gt_cve = _write(tmp_path / "gt_cve.json", [{"cve_id": c} for c in CVE_IDS])
    return gt_config, gt_cve


def _gt_finding(rule_id, scope="ground_truth", ground_truth=True):
    return {
        "rule_id": rule_id,
        "name": rule_id,
        "severity": "HIGH",
        "category": "config",
        "file_path": "config.inc.php",
        "line_start": 1,
        "ground_truth": ground_truth,
        "evaluation_scope": scope,
    }


def _scan(tmp_path, name, version, findings):
    payload = {"ojs_version": version, "findings": findings}
    return _write(tmp_path / name, payload)


def _by_version(result):
    return {pv["ojs_version"]: pv for pv in result["per_version"]}


def test_strict_gt_version_aware_denominator_differs_by_ojs_version(tmp_path):
    gt_config, gt_cve = _gt_files(tmp_path)
    scans = [
        _scan(tmp_path, "s24.json", "2.4.7-1", [_gt_finding("OJS-CFG-SEC-001")]),
        _scan(tmp_path, "s33.json", "3.3.0-13", [_gt_finding("OJS-CFG-SEC-001")]),
        _scan(tmp_path, "s34.json", "3.4.0-7", [_gt_finding("OJS-CFG-SEC-001")]),
    ]

    result = evaluate_sast.evaluate_scan_results(
        scans, gt_config, gt_cve, ruleset_dir=None, scope="strict-gt-version-aware"
    )
    by = _by_version(result)

    # Total GT universe is constant (39 config + 12 CVE) ...
    assert result["total_gt"] == 51
    # ... but the applicable denominator differs per version (matches ground truth).
    assert by["2.4.7-1"]["expected_applicable_gt"] == 2     # CVE-SRC-010, 011
    assert by["3.3.0-13"]["expected_applicable_gt"] == 40   # 32 config + 8 CVE
    assert by["3.4.0-7"]["expected_applicable_gt"] == 39    # 34 config + 5 CVE
    assert (
        by["2.4.7-1"]["expected_applicable_gt"]
        < by["3.4.0-7"]["expected_applicable_gt"]
    )


def test_non_applicable_gt_finding_counted_as_version_fp(tmp_path):
    gt_config, gt_cve = _gt_files(tmp_path)
    # OJS-CFG-SEC-013 (app_key) is a 3.5-only directive; firing it on a 3.3 scan
    # is a version false positive, not a true positive.
    scan = _scan(
        tmp_path, "s33.json", "3.3.0-13",
        [_gt_finding("OJS-CFG-SEC-001"), _gt_finding("OJS-CFG-SEC-013")],
    )
    result = evaluate_sast.evaluate_scan_results(
        [scan], gt_config, gt_cve, ruleset_dir=None, scope="strict-gt-version-aware"
    )
    pv = result["per_version"][0]

    assert "OJS-CFG-SEC-013" in pv["version_false_positives"]
    assert "OJS-CFG-SEC-013" not in pv["false_negatives"]
    assert pv["version_fp"] == 1
    assert pv["tp"] == 1                      # only SEC-001 counts
    assert pv["fp"] == 0                      # SEC-013 is GT, so not a plain FP
    assert pv["precision"] == 1.0            # strict precision ignores version_fp
    assert pv["version_adjusted_precision"] == 0.5  # version-adjusted penalises it


def test_extension_generic_upload_not_counted_as_version_fp(tmp_path):
    gt_config, gt_cve = _gt_files(tmp_path)
    findings = [
        _gt_finding("OJS-CFG-SEC-001"),
        # Non strict-GT findings must be ignored entirely by the version-aware scope.
        _gt_finding("OJS-CFG-NGX-001", scope="extension", ground_truth=False),
        _gt_finding("RULE-SRC-010", scope="generic", ground_truth=False),
        _gt_finding("RULE-UPLOAD-001", scope="upload", ground_truth=False),
    ]
    scan = _scan(tmp_path, "s33.json", "3.3.0-13", findings)
    result = evaluate_sast.evaluate_scan_results(
        [scan], gt_config, gt_cve, ruleset_dir=None, scope="strict-gt-version-aware"
    )
    pv = result["per_version"][0]

    for noise in ("OJS-CFG-NGX-001", "RULE-SRC-010", "RULE-UPLOAD-001"):
        assert noise not in pv["version_false_positives"]
        assert noise not in pv["false_positives"]
    assert pv["tp"] == 1
    assert pv["version_fp"] == 0
    assert pv["fp"] == 0


def test_ojs24_config_gt_not_counted_when_config_gt_starts_at_33(tmp_path):
    gt_config, gt_cve = _gt_files(tmp_path)
    # A 2.4 scan that emitted several config GT rules (all >= 3.3) plus an old CVE.
    scan = _scan(
        tmp_path, "s24.json", "2.4.7-1",
        [
            _gt_finding("OJS-CFG-SEC-001"),
            _gt_finding("OJS-CFG-DBG-001"),
            _gt_finding("CVE-SRC-011"),
        ],
    )
    result = evaluate_sast.evaluate_scan_results(
        [scan], gt_config, gt_cve, ruleset_dir=None, scope="strict-gt-version-aware"
    )
    pv = result["per_version"][0]

    # No config GT applies to OJS 2.4 -> config findings become version_fp.
    assert "OJS-CFG-SEC-001" in pv["version_false_positives"]
    assert "OJS-CFG-DBG-001" in pv["version_false_positives"]
    # Only CVE-SRC-011 (old deserialization) is a genuine applicable TP.
    assert pv["tp"] == 1
    assert pv["expected_applicable_gt"] == 2  # CVE-SRC-010, 011 only
    # None of the config GT rules count toward TP for OJS 2.4.
    assert all(not fp.startswith("OJS-CFG") for fp in pv["false_positives"])


def test_ojs34_35_only_rule_is_version_fp(tmp_path):
    gt_config, gt_cve = _gt_files(tmp_path)
    scan = _scan(
        tmp_path, "s34.json", "3.4.0-7",
        [_gt_finding("OJS-CFG-GEN-007"), _gt_finding("OJS-CFG-SEC-013")],
    )
    result = evaluate_sast.evaluate_scan_results(
        [scan], gt_config, gt_cve, ruleset_dir=None, scope="strict-gt-version-aware"
    )
    pv = result["per_version"][0]

    # GEN-007 (3.4, 3.5) applies to 3.4 -> TP; SEC-013 (3.5 only) -> version_fp.
    assert "OJS-CFG-SEC-013" in pv["version_false_positives"]
    assert "OJS-CFG-GEN-007" not in pv["version_false_positives"]
    assert pv["tp"] == 1
    assert pv["version_fp"] == 1


def test_other_scopes_still_flat(tmp_path):
    """Legacy scopes keep returning a flat result (backward compatibility)."""
    gt_config, gt_cve = _gt_files(tmp_path)
    scan = _scan(tmp_path, "s33.json", "3.3.0-13", [_gt_finding("OJS-CFG-SEC-001")])
    result = evaluate_sast.evaluate_scan_results(
        [scan], gt_config, gt_cve, ruleset_dir=None, scope="strict-gt"
    )
    assert "per_version" not in result
    assert result["tp"] == 1
