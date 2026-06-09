"""Regression tests for the SAST-engine audit fixes.

These cover four independent defects found while auditing the ``source_code``
module:

* #1  Ground-truth / evaluation-scope tagging was coupled to the rule-id *prefix*
      (``CVE-SRC-`` …), so an equivalent CVE ruleset renamed to ``OJS-CVE-…``
      produced correct findings that the evaluator scored as 0%.
* #2  ``is_version_affected`` AND-ed every ``>=`` floor, so a multi-branch
      affected range silently excluded earlier branches.
* #3  PHP source/sink matching was line-by-line, silently missing any construct
      that spanned multiple lines.
* #4  A rule whose ``vulnerability_type`` mapped to no detector was dropped
      silently instead of being surfaced.
"""

import importlib.util
from pathlib import Path

import pytest

from ojs_sast.detectors.cve_scanner import CVEScanner, _BaseDetector
from ojs_sast.helpers.version_utils import is_version_affected
from ojs_sast.models import Finding, Rule, Severity, resolve_rule_metadata
from ojs_sast.ruleset.loader import Ruleset

_EVAL_SPEC = importlib.util.spec_from_file_location(
    "evaluate_sast",
    Path(__file__).resolve().parents[1] / "scripts" / "evaluate_sast.py",
)
evaluate_sast = importlib.util.module_from_spec(_EVAL_SPEC)
assert _EVAL_SPEC.loader is not None
_EVAL_SPEC.loader.exec_module(evaluate_sast)


# --------------------------------------------------------------------------- #
# #1 — ground-truth tagging is no longer coupled to the rule-id prefix
# --------------------------------------------------------------------------- #
def test_renamed_cve_rule_is_ground_truth_via_params():
    meta = resolve_rule_metadata(
        "OJS-CVE-2023-5626",
        {"cve_id": "CVE-2023-5626", "vulnerability_type": "csrf"},
    )
    assert meta["ground_truth"] is True
    assert meta["evaluation_scope"] == "ground_truth"


def test_renamed_cve_rule_is_ground_truth_from_id_alone():
    # Even without params (the Finding.to_dict fallback path) an id that embeds a
    # CVE number is recognised as ground truth.
    meta = resolve_rule_metadata("OJS-CVE-2023-5894")
    assert meta["ground_truth"] is True
    assert meta["evaluation_scope"] == "ground_truth"


def test_generic_rule_without_cve_signal_stays_non_ground_truth():
    # A generic heuristic rule (vulnerability_type but no CVE identity) must NOT be
    # promoted to ground truth.
    meta = resolve_rule_metadata(
        "SAST-SRC-LESS-001", {"vulnerability_type": "less_variable_injection"}
    )
    assert meta["ground_truth"] is None
    assert meta["evaluation_scope"] is None


def test_existing_prefix_behaviour_is_unchanged():
    assert resolve_rule_metadata("CVE-SRC-5626")["ground_truth"] is True
    assert resolve_rule_metadata("OJS-CFG-NGX-001")["ground_truth"] is False
    assert resolve_rule_metadata("OJS-CFG-NGX-001")["evaluation_scope"] == "extension"
    assert resolve_rule_metadata("RULE-SRC-001")["evaluation_scope"] == "generic"


def test_renamed_rule_finding_selected_by_strict_gt_evaluator():
    rule = Rule(
        id="OJS-CVE-2023-5626",
        name="renamed csrf rule",
        module="source_code",
        severity=Severity.HIGH,
        params={"cve_id": "CVE-2023-5626", "vulnerability_type": "csrf"},
    )
    finding = Finding(
        rule_id=rule.id,
        module="source_code",
        severity=Severity.HIGH,
        file_path="classes/subscription/form/PaymentTypesForm.inc.php",
        **resolve_rule_metadata(rule.id, rule.params),
    )
    data = finding.to_dict()
    assert data["ground_truth"] is True
    # The default strict-gt scope now keeps the finding instead of discarding it.
    assert evaluate_sast.is_strict_gt_finding(data) is True
    assert evaluate_sast.select_predicted_rule_ids([data], "strict-gt") == {
        "OJS-CVE-2023-5626"
    }


# --------------------------------------------------------------------------- #
# #2 — multi-branch affected_versions
# --------------------------------------------------------------------------- #
def test_multi_branch_affected_versions_match_earlier_branch():
    # (<3.3.0-16) OR (>=3.4.0 AND <3.4.0-4): 3.3.0-7 is affected via the 3.3 branch.
    affected = ["<3.3.0-16", ">=3.4.0", "<3.4.0-4"]
    assert is_version_affected("3.3.0-7", affected)[0] is True
    assert is_version_affected("3.4.0-2", affected)[0] is True
    # 3.4.0-5 is past the 3.4 ceiling and not in the 3.3 branch -> not affected.
    assert is_version_affected("3.4.0-5", affected)[0] is False


def test_per_branch_floor_ceiling_pairs():
    affected = [">=3.3.0", "<=3.3.0-21", ">=3.4.0", "<=3.4.0-9", ">=3.5.0", "<=3.5.0-1"]
    assert is_version_affected("3.3.0-7", affected)[0] is True
    assert is_version_affected("3.4.0-7", affected)[0] is True
    assert is_version_affected("3.5.0-1", affected)[0] is True


def test_contiguous_config_range_still_excludes_old_versions():
    # A single floor+ceiling pair keeps AND semantics: 2.4 must stay excluded.
    affected = [">=3.3.0", "<3.6.0"]
    assert is_version_affected("2.4.7-1", affected)[0] is False
    assert is_version_affected("3.4.0-7", affected)[0] is True


# --------------------------------------------------------------------------- #
# #3 — PHP source/sink matching now handles multi-line constructs
# --------------------------------------------------------------------------- #
def test_php_sink_pattern_matches_across_lines():
    src = "<?php\n$issueFile->setServerFileName(\n    $o->textContent\n);\n"
    pattern = r"setServerFileName\s*\(\s*\$o->textContent\s*\)"
    # Line-by-line matching missed this; the multiline fallback now finds it.
    assert _BaseDetector._check_sink_patterns(src, [pattern]) is not None


def test_single_line_match_is_unchanged():
    src = "<?php $issueFile->setServerFileName($o->textContent);"
    pattern = r"setServerFileName\s*\(\s*\$o->textContent\s*\)"
    hit = _BaseDetector._check_sink_patterns(src, [pattern])
    assert hit is not None
    assert hit[1] == 1  # line number preserved


# --------------------------------------------------------------------------- #
# #4 — unroutable vulnerability_type is surfaced, not dropped silently
# --------------------------------------------------------------------------- #
def test_unroutable_vulnerability_type_is_reported():
    rule = Rule(
        id="OJS-CVE-9999-0001",
        name="rule with unknown type",
        module="source_code",
        severity=Severity.HIGH,
        params={"vulnerability_type": "xxe", "file_path_patterns": [r"x\.php$"]},
    )
    scanner = CVEScanner(Ruleset([rule]))
    assert ("OJS-CVE-9999-0001", "xxe") in scanner.unroutable_rules


def test_recognised_vulnerability_type_is_not_reported():
    rule = Rule(
        id="OJS-CVE-2023-5626",
        name="rule with known type",
        module="source_code",
        severity=Severity.HIGH,
        params={"vulnerability_type": "csrf", "file_path_patterns": [r"x\.php$"]},
    )
    scanner = CVEScanner(Ruleset([rule]))
    assert scanner.unroutable_rules == []
