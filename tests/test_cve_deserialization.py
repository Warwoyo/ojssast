"""Tests for PHP deserialization CVE detector (CVE-SRC-011)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ojs_sast.helpers.php_utils import find_request_variables, find_unserialize_sinks
from ojs_sast.detectors.cve_scanner import CVEScanner

FIXTURES = Path(__file__).parent / "fixtures" / "ojs_cve_p1"

# --------------------------------------------------------------------------- #
# find_request_variables
# --------------------------------------------------------------------------- #

FILTERS_PHP = """\
<?php
class Foo {
    function bar($request) {
        $filters = $request->getUserVar('filters');
        $orderBy = $request->getUserVar('orderBy');
        $safe = 'static';
    }
}
"""


def test_find_request_variables_finds_filters():
    result = find_request_variables(FILTERS_PHP, {"filters"})
    assert "$filters" in result


def test_find_request_variables_finds_orderby():
    result = find_request_variables(FILTERS_PHP, {"orderBy"})
    assert "$orderBy" in result


def test_find_request_variables_ignores_static():
    result = find_request_variables(FILTERS_PHP, {"filters"})
    assert "$safe" not in result


def test_find_request_variables_static_call():
    code = "<?php $f = Request::getUserVar('filters');"
    result = find_request_variables(code, {"filters"})
    assert "$f" in result


def test_find_request_variables_chained_call():
    code = "<?php $f = $this->getRequest()->getUserVar('filters');"
    result = find_request_variables(code, {"filters"})
    assert "$f" in result


# --------------------------------------------------------------------------- #
# find_unserialize_sinks
# --------------------------------------------------------------------------- #

UNSER_PHP = """\
<?php
$a = unserialize($filters);
$b = @unserialize($data);
$c = unserialize(base64_decode($orderBy));
$d = json_decode($safe, true);
"""


def test_find_unserialize_sinks_direct():
    sinks = find_unserialize_sinks(UNSER_PHP, {"$filters"})
    assert len(sinks) >= 1
    assert any("$filters" in s.snippet for s in sinks)


def test_find_unserialize_sinks_at_suppressed():
    sinks = find_unserialize_sinks(UNSER_PHP, {"$data"})
    assert len(sinks) >= 1


def test_find_unserialize_sinks_base64_wrapper():
    sinks = find_unserialize_sinks(UNSER_PHP, {"$orderBy"})
    assert len(sinks) >= 1


def test_find_unserialize_sinks_json_decode_not_returned():
    sinks = find_unserialize_sinks(UNSER_PHP, {"$safe"})
    assert sinks == []


# --------------------------------------------------------------------------- #
# CVE-SRC-011: full scanner
# --------------------------------------------------------------------------- #

VULN_PHP = """\
<?php
class PKPStatisticsHelper {
    function generateReport($request) {
        $filters = $request->getUserVar('filters');
        $filters = unserialize($filters);
    }
}
"""

VULN_PHP_REQUEST_STATIC = """\
<?php
class PKPStatisticsHelper {
    function generateReport(&$request) {
        $filters = Request::getUserVar('filters');
        $filters = unserialize($filters);
    }
}
"""

VULN_PHP_BASE64 = """\
<?php
class PKPStatisticsHelper {
    function generateReport($request) {
        $orderBy = $request->getUserVar('orderBy');
        $data = unserialize(base64_decode($orderBy));
    }
}
"""

SAFE_PHP_JSON_DECODE = """\
<?php
class PKPStatisticsHelper {
    function generateReport($request) {
        $filters = $request->getUserVar('filters');
        $filters = json_decode($filters, true);
    }
}
"""

SAFE_PHP_TRUSTED = """\
<?php
class PKPStatisticsHelper {
    function generateReport($request) {
        $filters = unserialize($trustedInternalCache);
    }
}
"""


def _scan(ruleset, source: str, rel: str):
    scanner = CVEScanner(ruleset)
    findings = scanner.scan_file(Path(rel), rel, source.encode(), source)
    return {f.rule_id for f in findings}


def test_cve_src_011_detects_getuservar_filters_to_unserialize(ruleset):
    ids = _scan(ruleset, VULN_PHP, "classes/statistics/PKPStatisticsHelper.inc.php")
    assert "CVE-SRC-011" in ids, f"Expected CVE-SRC-011 in: {ids}"


def test_cve_src_011_detects_static_request_call(ruleset):
    ids = _scan(ruleset, VULN_PHP_REQUEST_STATIC, "classes/statistics/PKPStatisticsHelper.inc.php")
    assert "CVE-SRC-011" in ids, f"Expected CVE-SRC-011 in: {ids}"


def test_cve_src_011_detects_base64_decode_wrapper(ruleset):
    ids = _scan(ruleset, VULN_PHP_BASE64, "classes/statistics/PKPStatisticsHelper.inc.php")
    assert "CVE-SRC-011" in ids, f"Expected CVE-SRC-011 in: {ids}"


def test_cve_src_011_detects_lib_pkp_path_variant(ruleset):
    ids = _scan(
        ruleset, VULN_PHP,
        "lib/pkp/classes/statistics/PKPStatisticsHelper.inc.php",
    )
    assert "CVE-SRC-011" in ids, f"Expected CVE-SRC-011 for lib/pkp path"


def test_cve_src_011_detects_php_extension_variant(ruleset):
    ids = _scan(ruleset, VULN_PHP, "classes/statistics/PKPStatisticsHelper.php")
    assert "CVE-SRC-011" in ids, f"Expected CVE-SRC-011 for .php extension"


def test_cve_src_011_does_not_flag_json_decode(ruleset):
    ids = _scan(ruleset, SAFE_PHP_JSON_DECODE, "classes/statistics/PKPStatisticsHelper.inc.php")
    assert "CVE-SRC-011" not in ids


def test_cve_src_011_does_not_flag_trusted_unserialize(ruleset):
    ids = _scan(ruleset, SAFE_PHP_TRUSTED, "classes/statistics/PKPStatisticsHelper.inc.php")
    assert "CVE-SRC-011" not in ids


def test_cve_src_011_with_fixture_file(ruleset):
    scanner = CVEScanner(ruleset)
    php_path = FIXTURES / "classes" / "statistics" / "PKPStatisticsHelper.inc.php"
    rel = "classes/statistics/PKPStatisticsHelper.inc.php"
    text = php_path.read_text(encoding="utf-8")
    findings = scanner.scan_file(php_path, rel, text.encode(), text)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-011" in rule_ids, f"Expected CVE-SRC-011 from fixture, got: {rule_ids}"


def test_cve_src_011_safe_patch_scoped_not_suppressed_by_other_function(ruleset):
    """json_decode in an unrelated function must NOT suppress the CVE finding."""
    source = """\
<?php
class PKPStatisticsHelper {
    function generateReport($request) {
        $filters = $request->getUserVar('filters');
        $filters = unserialize($filters);
    }

    function safeMethod($request) {
        $data = json_decode($request->getUserVar('data'), true);
    }
}
"""
    ids = _scan(ruleset, source, "classes/statistics/PKPStatisticsHelper.inc.php")
    assert "CVE-SRC-011" in ids, "json_decode in safeMethod should NOT suppress finding in generateReport"


# --------------------------------------------------------------------------- #
# CVE-SRC-011: OJS 2.x paths and alternative function names
# --------------------------------------------------------------------------- #

VULN_PHP_EXECUTE = """\
<?php
class PKPToolsHandler extends Handler {
    function execute($args, $request) {
        $filters = $request->getUserVar('filters');
        $filters = unserialize($filters);
        $orderBy = $request->getUserVar('orderBy');
        $data = unserialize(base64_decode($orderBy));
    }
}
"""


def test_cve_src_011_detects_execute_function_name(ruleset):
    """execute() is a valid function_names variant for CVE-SRC-011."""
    ids = _scan(ruleset, VULN_PHP_EXECUTE, "pages/management/PKPToolsHandler.inc.php")
    assert "CVE-SRC-011" in ids, f"execute() variant not detected: {ids}"


def test_cve_src_011_detects_ojs2_manager_path(ruleset):
    """pages/manager/ is the OJS 2.x path for PKPToolsHandler."""
    ids = _scan(ruleset, VULN_PHP_EXECUTE, "pages/manager/PKPToolsHandler.inc.php")
    assert "CVE-SRC-011" in ids, f"OJS 2.x manager path not detected: {ids}"


def test_cve_src_011_detects_lib_pkp_manager_path(ruleset):
    """lib/pkp/pages/manager/ path variant must also be detected."""
    ids = _scan(ruleset, VULN_PHP_EXECUTE, "lib/pkp/pages/manager/PKPToolsHandler.inc.php")
    assert "CVE-SRC-011" in ids, f"lib/pkp/pages/manager path not detected: {ids}"


def test_cve_src_011_manager_fixture_file_detected(ruleset):
    """Scan the OJS 2.x pages/manager fixture file and expect CVE-SRC-011."""
    scanner = CVEScanner(ruleset)
    fixture_dir = Path(__file__).parent / "fixtures" / "ojs_cve_p1"
    php_path = fixture_dir / "pages" / "manager" / "PKPToolsHandler.inc.php"
    rel = "pages/manager/PKPToolsHandler.inc.php"
    text = php_path.read_text(encoding="utf-8")
    findings = scanner.scan_file(php_path, rel, text.encode(), text)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-011" in rule_ids, f"Expected CVE-SRC-011 from manager fixture, got: {rule_ids}"


def test_cve_src_011_execute_safe_patch_scoped(ruleset):
    """json_decode in a sibling function must NOT suppress unserialize in execute()."""
    source = """\
<?php
class PKPToolsHandler extends Handler {
    function execute($args, $request) {
        $filters = $request->getUserVar('filters');
        $filters = unserialize($filters);
    }

    function fetchReport($request) {
        $data = json_decode($request->getUserVar('data'), true);
    }
}
"""
    ids = _scan(ruleset, source, "pages/manager/PKPToolsHandler.inc.php")
    assert "CVE-SRC-011" in ids, "json_decode in fetchReport must NOT suppress finding in execute()"
