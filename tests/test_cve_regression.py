"""Regression tests for CVE-oriented source matching helpers and P1 end-to-end."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from ojs_sast.helpers.php_utils import find_all_pattern_spans, find_pattern_span
from ojs_sast.helpers.path_utils import matches_cve_path, normalize_ojs_path
from ojs_sast.detectors.cve_scanner import CVEScanner

FIXTURES = Path(__file__).parent / "fixtures" / "ojs_cve_p1"


# --------------------------------------------------------------------------- #
# normalize_ojs_path
# --------------------------------------------------------------------------- #

def test_normalize_ojs_path_strips_lib_pkp_prefix():
    assert normalize_ojs_path("lib/pkp/classes/statistics/PKPStatisticsHelper.inc.php") == \
        "classes/statistics/PKPStatisticsHelper.inc.php"


def test_normalize_ojs_path_strips_pkp_lib_prefix():
    assert normalize_ojs_path("pkp-lib/classes/statistics/PKPStatisticsHelper.inc.php") == \
        "classes/statistics/PKPStatisticsHelper.inc.php"


def test_normalize_ojs_path_no_prefix_unchanged():
    p = "classes/statistics/PKPStatisticsHelper.inc.php"
    assert normalize_ojs_path(p) == p


def test_normalize_ojs_path_strips_leading_slash():
    assert normalize_ojs_path("/classes/core/PKPApplication.php") == \
        "classes/core/PKPApplication.php"


# --------------------------------------------------------------------------- #
# matches_cve_path: inc.php ↔ .php aliasing
# --------------------------------------------------------------------------- #

def test_matches_cve_path_php_inc_alias_forward():
    patterns = ["classes/statistics/PKPStatisticsHelper.inc.php"]
    assert matches_cve_path("classes/statistics/PKPStatisticsHelper.php", patterns)


def test_matches_cve_path_php_inc_alias_reverse():
    patterns = ["classes/statistics/PKPStatisticsHelper.php"]
    assert matches_cve_path("classes/statistics/PKPStatisticsHelper.inc.php", patterns)


def test_matches_cve_path_lib_pkp_alias_with_prefix():
    """Rule path without lib/pkp/ prefix should match file WITH prefix."""
    patterns = ["classes/statistics/PKPStatisticsHelper.inc.php"]
    assert matches_cve_path(
        "lib/pkp/classes/statistics/PKPStatisticsHelper.inc.php", patterns
    )


def test_matches_cve_path_lib_pkp_alias_no_double_match():
    """Different basename must NOT match."""
    patterns = ["classes/statistics/PKPStatisticsHelper.inc.php"]
    assert not matches_cve_path("classes/statistics/OtherHelper.inc.php", patterns)


def test_matches_cve_path_tpl_exact():
    patterns = ["templates/frontend/pages/submissions.tpl"]
    assert matches_cve_path("templates/frontend/pages/submissions.tpl", patterns)
    assert not matches_cve_path("templates/frontend/pages/search.tpl", patterns)


def test_find_pattern_span_single_line_match():
    source = "<?php\necho $_GET['q'];\n"

    match = find_pattern_span(source, r"echo\s+\$_GET\['q'\];")

    assert match is not None
    assert match.pattern == r"echo\s+\$_GET\['q'\];"
    assert match.start == source.index("echo")
    assert match.end == source.index(";") + 1
    assert match.line_start == 2
    assert match.line_end == 2
    assert match.snippet == "echo $_GET['q'];"


def test_find_pattern_span_multiline_match_uses_dotall():
    source = "<?php\nif ($ok) {\n    echo $_POST['name'];\n}\n"

    match = find_pattern_span(source, r"if\s*\(\$ok\).*echo\s+\$_POST")

    assert match is not None
    assert match.line_start == 2
    assert match.line_end == 3
    assert match.snippet == "if ($ok) {\n    echo $_POST"


def test_find_pattern_span_no_match():
    source = "<?php\necho 'safe';\n"

    assert find_pattern_span(source, r"\$_REQUEST") is None


def test_find_pattern_span_line_start_and_line_end_are_accurate():
    source = "line 1\nline 2\nstart\nmiddle\nend\nline 6\n"

    match = find_pattern_span(source, r"start\nmiddle\nend")

    assert match is not None
    assert match.line_start == 3
    assert match.line_end == 5


# --------------------------------------------------------------------------- #
# find_all_pattern_spans
# --------------------------------------------------------------------------- #

def test_find_all_pattern_spans_returns_multiple_matches():
    source = "line1\n{$foo}\nline3\n{$foo}\n"
    matches = find_all_pattern_spans(source, r"\{\$foo\}")
    assert len(matches) == 2


def test_find_all_pattern_spans_empty_on_no_match():
    source = "nothing here"
    assert find_all_pattern_spans(source, r"\{XYZ\}") == []


def test_find_all_pattern_spans_multiline():
    source = "before\n{translate\n    name=foo\n}\nafter"
    matches = find_all_pattern_spans(source, r"\{translate[^{}]*\}", re.IGNORECASE | re.DOTALL)
    assert len(matches) == 1
    assert matches[0].line_start == 2
    assert matches[0].line_end == 4


# --------------------------------------------------------------------------- #
# P1-F: End-to-end synthetic scan — all three missing CVEs
# --------------------------------------------------------------------------- #

def _make_ojs_tree(dst: Path) -> None:
    """Copy P1 fixtures into a minimal OJS directory tree under dst."""
    shutil.copytree(FIXTURES, dst / "ojs", dirs_exist_ok=False)


def _scan_file(scanner: CVEScanner, path: Path, root: Path) -> set:
    rel = str(path.relative_to(root)).replace("\\", "/")
    raw = path.read_bytes()
    findings = scanner.scan_file(path, rel, raw)
    return {f.rule_id for f in findings}


def test_p1_cve_regression_detects_all_three_missing_cves(ruleset, tmp_path):
    """The three structured source CVEs must be detected against synthetic fixtures.

    Maps to CVE-2018-12229 (search XSS), CVE-2019-19909 (deserialization) and
    CVE-2023-5903 (section-title stored XSS).
    """
    root = tmp_path
    _make_ojs_tree(root)
    ojs = root / "ojs"

    scanner = CVEScanner(ruleset)
    detected = set()

    for php_file in ojs.rglob("*.php"):
        detected |= _scan_file(scanner, php_file, ojs)
    for tpl_file in ojs.rglob("*.tpl"):
        detected |= _scan_file(scanner, tpl_file, ojs)
    for inc_file in ojs.rglob("*.inc.php"):
        detected |= _scan_file(scanner, inc_file, ojs)

    missing = {"CVE-SRC-12229", "CVE-SRC-19909", "CVE-SRC-5903"} - detected
    assert not missing, f"Still missing CVEs: {missing} (detected: {detected})"
