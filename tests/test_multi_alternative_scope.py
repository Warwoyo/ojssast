"""Tests for multi-alternative scope matching (function_names / class_names).

Different OJS versions sometimes rename the class or method that hosts a known
vulnerability while the dangerous source→sink flow stays the same. A rule must
therefore be able to list *alternative* class/function names and fire when any
one of them is present in the scanned file — exactly the OR semantics already
used for file_path_patterns / source_patterns / sink_patterns / safe_patch_patterns.

These tests cover:
  * the ``_collect_scope_names`` merge/dedup/wildcard-drop helper;
  * ``_resolve_function_scope`` alternative resolution and bail behaviour;
  * end-to-end detection through ``CVEScanner`` for path-traversal (function_names)
    and CSRF (class_names), plus the wildcard-class regression.
"""

from __future__ import annotations

from pathlib import Path

from ojs_sast.detectors.cve_scanner import (
    CVEScanner,
    _BaseDetector,
    _collect_scope_names,
)
from ojs_sast.models import Rule, Severity
from ojs_sast.ruleset.loader import Ruleset


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _make_rule(rule_id: str, vuln_type: str, **params) -> Rule:
    base = {"vulnerability_type": vuln_type, "affected_versions": [">=3.0.0"]}
    base.update(params)
    return Rule(
        id=rule_id,
        name=rule_id,
        module="source_code",
        severity=Severity.HIGH,
        pattern_type="cve",
        params=base,
    )


def _scan(rule: Rule, source: str, rel: str):
    scanner = CVEScanner(Ruleset([rule]))
    findings = scanner.scan_file(Path(rel), rel, source.encode(), source)
    return {f.rule_id for f in findings}, findings


# --------------------------------------------------------------------------- #
# _collect_scope_names
# --------------------------------------------------------------------------- #
def test_collect_scope_names_merges_singular_first():
    params = {"function_name": "init", "function_names": ["initPlugin", "boot"]}
    assert _collect_scope_names(params, "function_name", "function_names") == [
        "init", "initPlugin", "boot",
    ]


def test_collect_scope_names_dedups_and_preserves_order():
    params = {"function_name": "init", "function_names": ["init", "boot", "boot"]}
    assert _collect_scope_names(params, "function_name", "function_names") == ["init", "boot"]


def test_collect_scope_names_drops_wildcards_and_empty():
    params = {"class_name": "*", "class_names": ["", None, "Validation"]}
    assert _collect_scope_names(params, "class_name", "class_names") == ["Validation"]


def test_collect_scope_names_all_wildcard_is_empty():
    params = {"function_name": "*"}
    assert _collect_scope_names(params, "function_name", "function_names") == []


def test_collect_scope_names_list_only():
    params = {"function_names": ["a", "b"]}
    assert _collect_scope_names(params, "function_name", "function_names") == ["a", "b"]


# --------------------------------------------------------------------------- #
# _resolve_function_scope
# --------------------------------------------------------------------------- #
SRC_TWO_FUNCS = """\
<?php
class Helper {
    function alpha() { return 1; }
    function beta() { return 2; }
}
"""


def test_resolve_function_scope_no_names_is_whole_file():
    scope, bail = _BaseDetector._resolve_function_scope(SRC_TWO_FUNCS, {})
    assert scope is None and bail is False


def test_resolve_function_scope_single_present():
    scope, bail = _BaseDetector._resolve_function_scope(
        SRC_TWO_FUNCS, {"function_name": "alpha"}
    )
    assert bail is False and scope is not None and "alpha" in scope


def test_resolve_function_scope_single_absent_bails():
    scope, bail = _BaseDetector._resolve_function_scope(
        SRC_TWO_FUNCS, {"function_name": "missing"}
    )
    assert scope is None and bail is True


def test_resolve_function_scope_alternative_second_present():
    # First alternative absent, second present → resolves without bailing.
    scope, bail = _BaseDetector._resolve_function_scope(
        SRC_TWO_FUNCS, {"function_names": ["missing", "beta"]}
    )
    assert bail is False and scope is not None and "beta" in scope


def test_resolve_function_scope_all_alternatives_absent_bails():
    scope, bail = _BaseDetector._resolve_function_scope(
        SRC_TWO_FUNCS, {"function_names": ["nope1", "nope2"]}
    )
    assert scope is None and bail is True


def test_resolve_function_scope_wildcard_plus_alternatives():
    # A "*" singular alongside concrete alternatives still uses the alternatives.
    scope, bail = _BaseDetector._resolve_function_scope(
        SRC_TWO_FUNCS, {"function_name": "*", "function_names": ["beta"]}
    )
    assert bail is False and scope is not None and "beta" in scope


# --------------------------------------------------------------------------- #
# End-to-end: path traversal with function_names alternatives
# --------------------------------------------------------------------------- #
COVER_RENAMED_PHP = """\
<?php
class NativeXmlPublicationFilter {
    function parsePublicationCoverImage($node) {
        $coverImage['uploadName'] = $node->textContent;
        $filePath = $this->getContextFilesPath() . '/' . $coverImage['uploadName'];
        file_put_contents($filePath, base64_decode($node->textContent));
    }
}
"""

_PT_PARAMS = dict(
    file_path_patterns=[r"plugins/.*Filter\.php$"],
    source_patterns=["uploadName"],
    sink_patterns=["file_put_contents"],
    safe_patch_patterns=["preg_replace"],
)
_REL = "plugins/importexport/native/filter/NativeXmlPublicationFilter.php"


def test_path_traversal_detects_renamed_function_via_alternatives():
    rule = _make_rule(
        "CVE-SRC-ALT-PT",
        "path_traversal_arbitrary_file_write",
        function_names=["parsePublicationCover", "parsePublicationCoverImage"],
        **_PT_PARAMS,
    )
    ids, _ = _scan(rule, COVER_RENAMED_PHP, _REL)
    assert "CVE-SRC-ALT-PT" in ids, f"alternative function name not detected: {ids}"


def test_path_traversal_single_name_misses_renamed_function():
    # Without the alternative, the single (old) name is absent → no finding.
    rule = _make_rule(
        "CVE-SRC-ALT-PT2",
        "path_traversal_arbitrary_file_write",
        function_name="parsePublicationCover",
        **_PT_PARAMS,
    )
    ids, _ = _scan(rule, COVER_RENAMED_PHP, _REL)
    assert "CVE-SRC-ALT-PT2" not in ids


def test_path_traversal_all_alternatives_absent_no_finding():
    rule = _make_rule(
        "CVE-SRC-ALT-PT3",
        "path_traversal_arbitrary_file_write",
        function_names=["someOtherName", "anotherMissingName"],
        **_PT_PARAMS,
    )
    ids, _ = _scan(rule, COVER_RENAMED_PHP, _REL)
    assert "CVE-SRC-ALT-PT3" not in ids


# --------------------------------------------------------------------------- #
# End-to-end: CSRF with class_names alternatives + wildcard regression
# --------------------------------------------------------------------------- #
CSRF_PHP = """\
<?php
class PaymentTypesForm extends Form {
    function __construct() {
        parent::__construct();
        $this->updatePaymentSettings();
    }
}
"""


def test_csrf_detects_alternative_class_name():
    rule = _make_rule(
        "CVE-SRC-ALT-CSRF",
        "csrf",
        class_names=["PaymentForm", "PaymentTypesForm"],
        function_name="__construct",
        safe_patch_patterns=["validateCsrf", "addCheck.*FormValidatorCSRF"],
        file_path_patterns=[r".*Form\.php$"],
    )
    ids, findings = _scan(rule, CSRF_PHP, "classes/payment/PaymentTypesForm.php")
    assert "CVE-SRC-ALT-CSRF" in ids, f"alternative class name not detected: {ids}"
    assert any("__construct" in (f.matched_sink or "") for f in findings)


def test_csrf_missing_class_alternatives_no_finding():
    rule = _make_rule(
        "CVE-SRC-ALT-CSRF2",
        "csrf",
        class_names=["NotHere", "AlsoNotHere"],
        function_name="__construct",
        safe_patch_patterns=["validateCsrf"],
        file_path_patterns=[r".*Form\.php$"],
    )
    ids, _ = _scan(rule, CSRF_PHP, "classes/payment/PaymentTypesForm.php")
    assert "CVE-SRC-ALT-CSRF2" not in ids


def test_csrf_wildcard_class_no_longer_bails():
    """Regression: class_name '*' must mean 'no class restriction', not bail.

    Previously the CSRF detector ran extract_class_body(source, '*'), got None,
    and returned no finding even though the safe-patch check should drive it.
    """
    rule = _make_rule(
        "CVE-SRC-ALT-CSRF3",
        "csrf",
        class_name="*",
        function_name="*",
        safe_patch_patterns=["validateCsrf"],
        file_path_patterns=[r".*Form\.php$"],
    )
    ids, _ = _scan(rule, CSRF_PHP, "classes/payment/PaymentTypesForm.php")
    assert "CVE-SRC-ALT-CSRF3" in ids, "wildcard class wrongly suppressed the CSRF finding"
