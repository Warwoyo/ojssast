"""Tests for Smarty XSS CVE detectors (CVE-SRC-007, CVE-SRC-012)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ojs_sast.helpers.smarty_utils import (
    find_html_attribute_variable,
    find_translate_tag,
    smarty_expression_is_escaped,
)
from ojs_sast.helpers.php_utils import find_pattern_span
from ojs_sast.detectors.cve_scanner import CVEScanner

FIXTURES = Path(__file__).parent / "fixtures" / "ojs_cve_p1"


# --------------------------------------------------------------------------- #
# smarty_expression_is_escaped
# --------------------------------------------------------------------------- #

def test_smarty_expression_is_escaped_bare_escape():
    assert smarty_expression_is_escaped("getLocalizedTitle()|escape") is True


def test_smarty_expression_is_escaped_html_escape():
    assert smarty_expression_is_escaped("$authors|escape:'html'") is True


def test_smarty_expression_is_escaped_double_quote():
    assert smarty_expression_is_escaped('$authors|escape:"html"') is True


def test_smarty_expression_is_escaped_no_escape():
    assert smarty_expression_is_escaped("getLocalizedTitle()") is False


def test_smarty_expression_is_escaped_other_modifier():
    assert smarty_expression_is_escaped("$title|strip_tags") is False


# --------------------------------------------------------------------------- #
# find_translate_tag (multiline)
# --------------------------------------------------------------------------- #

TRANSLATE_MULTILINE = """\
{translate
    key="submission.section"
    name=$section->getLocalizedTitle()
}
"""

TRANSLATE_SINGLE_LINE = '{translate key="submission.section" name=$section->getLocalizedTitle()}'

TRANSLATE_ESCAPED = """\
{translate
    key="submission.section"
    name=$section->getLocalizedTitle()|escape
}
"""


def test_find_translate_tag_detects_multiline():
    tags = find_translate_tag(TRANSLATE_MULTILINE)
    assert len(tags) == 1
    line_no, tag, _ = tags[0]
    assert line_no == 1
    assert "getLocalizedTitle" in tag


def test_find_translate_tag_detects_single_line():
    tags = find_translate_tag(TRANSLATE_SINGLE_LINE)
    assert len(tags) == 1


def test_find_translate_tag_with_param_pattern_multiline():
    tags = find_translate_tag(TRANSLATE_MULTILINE, param_pattern=r"getLocalizedTitle")
    assert len(tags) == 1


def test_find_translate_tag_escaped_still_returned():
    """find_translate_tag returns ALL translate tags; caller checks escape."""
    tags = find_translate_tag(TRANSLATE_ESCAPED)
    assert len(tags) == 1
    _, tag, _ = tags[0]
    assert "escape" in tag


# --------------------------------------------------------------------------- #
# find_html_attribute_variable (multiline)
# --------------------------------------------------------------------------- #

INPUT_MULTILINE_UNSAFE = """\
<input
    type="text"
    name="authors"
    value="{$authors}"
>
"""

INPUT_SINGLE_LINE_UNSAFE = '<input type="text" name="authors" value="{$authors}">'

INPUT_MULTILINE_SAFE = """\
<input
    name="authors"
    value="{$authors|escape:'html'}"
>
"""

INPUT_SAFE_DOUBLE = '<input name="authors" value="{$authors|escape}">'


def test_find_html_attribute_variable_multiline_unsafe():
    hits = find_html_attribute_variable(INPUT_MULTILINE_UNSAFE, "value", r"\$authors")
    assert len(hits) == 1


def test_find_html_attribute_variable_single_line_unsafe():
    hits = find_html_attribute_variable(INPUT_SINGLE_LINE_UNSAFE, "value", r"\$authors")
    assert len(hits) == 1


def test_find_html_attribute_variable_safe_not_returned():
    hits = find_html_attribute_variable(INPUT_MULTILINE_SAFE, "value", r"\$authors")
    assert hits == []


def test_find_html_attribute_variable_safe_double_not_returned():
    hits = find_html_attribute_variable(INPUT_SAFE_DOUBLE, "value", r"\$authors")
    assert hits == []


# --------------------------------------------------------------------------- #
# CVE-SRC-007: multiline sink pattern with find_pattern_span
# --------------------------------------------------------------------------- #

def test_cve_src_007_sink_pattern_matches_multiline_translate():
    pattern = r"\{[^{}]*getLocalizedTitle\s*\(\s*\)(?!\s*\|escape)[^{}]*\}"
    tpl = TRANSLATE_MULTILINE
    hit = find_pattern_span(tpl, pattern, re.IGNORECASE | re.DOTALL)
    assert hit is not None
    assert "getLocalizedTitle" in (hit.snippet or "")


def test_cve_src_007_sink_pattern_matches_single_line_translate():
    pattern = r"\{[^{}]*getLocalizedTitle\s*\(\s*\)(?!\s*\|escape)[^{}]*\}"
    tpl = TRANSLATE_SINGLE_LINE
    hit = find_pattern_span(tpl, pattern, re.IGNORECASE | re.DOTALL)
    assert hit is not None


def test_cve_src_007_sink_pattern_no_match_when_escaped():
    pattern = r"\{[^{}]*getLocalizedTitle\s*\(\s*\)(?!\s*\|escape)[^{}]*\}"
    hit = find_pattern_span(TRANSLATE_ESCAPED, pattern, re.IGNORECASE | re.DOTALL)
    assert hit is None


def test_cve_src_007_sink_pattern_no_match_direct_escaped():
    pattern = r"\{[^{}]*getLocalizedTitle\s*\(\s*\)(?!\s*\|escape)[^{}]*\}"
    safe = "{$section->getLocalizedTitle()|escape}"
    hit = find_pattern_span(safe, pattern, re.IGNORECASE | re.DOTALL)
    assert hit is None


# --------------------------------------------------------------------------- #
# CVE-SRC-007: full scanner with fixture
# --------------------------------------------------------------------------- #

def test_cve_src_007_detects_multiline_translate_unescaped(ruleset):
    scanner = CVEScanner(ruleset)
    tpl_path = FIXTURES / "templates" / "frontend" / "pages" / "submissions.tpl"
    rel = "templates/frontend/pages/submissions.tpl"
    text = tpl_path.read_text(encoding="utf-8")
    findings = scanner.scan_file(tpl_path, rel, text.encode(), text)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-5903" in rule_ids, f"Expected CVE-SRC-007, got: {rule_ids}"


def test_cve_src_007_ignores_escaped_get_localized_title(ruleset):
    scanner = CVEScanner(ruleset)
    safe_tpl = """\
{translate
    key="submission.section"
    name=$section->getLocalizedTitle()|escape
}
"""
    rel = "templates/frontend/pages/submissions.tpl"
    findings = scanner.scan_file(Path(rel), rel, safe_tpl.encode(), safe_tpl)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-5903" not in rule_ids


# --------------------------------------------------------------------------- #
# CVE-SRC-012: multiline sink pattern
# --------------------------------------------------------------------------- #

def test_cve_src_012_sink_pattern_matches_multiline_input():
    pattern = r"\{\s*\$authors\b(?![^}]*\|\s*escape)[^}]*\}"
    tpl = INPUT_MULTILINE_UNSAFE
    hit = find_pattern_span(tpl, pattern, re.IGNORECASE | re.DOTALL)
    assert hit is not None


def test_cve_src_012_sink_pattern_no_match_when_escaped():
    pattern = r"\{\s*\$authors\b(?![^}]*\|\s*escape)[^}]*\}"
    hit = find_pattern_span(INPUT_MULTILINE_SAFE, pattern, re.IGNORECASE | re.DOTALL)
    assert hit is None


# --------------------------------------------------------------------------- #
# CVE-SRC-012: full scanner with fixture
# --------------------------------------------------------------------------- #

def test_cve_src_012_detects_multiline_authors_value_unescaped(ruleset):
    scanner = CVEScanner(ruleset)
    tpl_path = FIXTURES / "templates" / "frontend" / "pages" / "search.tpl"
    rel = "templates/frontend/pages/search.tpl"
    text = tpl_path.read_text(encoding="utf-8")
    findings = scanner.scan_file(tpl_path, rel, text.encode(), text)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" in rule_ids, f"Expected CVE-SRC-012, got: {rule_ids}"


def test_cve_src_012_ignores_escaped_authors_value(ruleset):
    scanner = CVEScanner(ruleset)
    safe_tpl = """\
<form>
    <input type="text" name="authors" value="{$authors|escape}">
</form>
"""
    rel = "templates/frontend/pages/search.tpl"
    findings = scanner.scan_file(Path(rel), rel, safe_tpl.encode(), safe_tpl)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" not in rule_ids


def test_cve_src_012_ignores_escaped_html_modifier(ruleset):
    scanner = CVEScanner(ruleset)
    safe_tpl = """\
<form>
    <input
        name="authors"
        value="{$authors|escape:'html'}"
    >
</form>
"""
    rel = "templates/frontend/pages/search.tpl"
    findings = scanner.scan_file(Path(rel), rel, safe_tpl.encode(), safe_tpl)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" not in rule_ids


# --------------------------------------------------------------------------- #
# CVE-SRC-012: realistic mixed-content (other fields escaped, authors not)
# --------------------------------------------------------------------------- #

REALISTIC_FIXTURES = Path(__file__).parent / "fixtures" / "ojs_cve_p1_realistic"


def test_cve_src_012_not_suppressed_when_other_fields_escaped(ruleset):
    """File-level $authors|escape in display context must NOT suppress value attribute finding."""
    scanner = CVEScanner(ruleset)
    tpl = """\
{if $authors}
    <p>{$authors|escape}</p>
{/if}
<form>
    <input type="text" name="authors" value="{$authors}">
</form>
"""
    rel = "templates/frontend/pages/search.tpl"
    findings = scanner.scan_file(Path(rel), rel, tpl.encode(), tpl)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" in rule_ids, (
        "Should detect even when $authors|escape appears in a display context"
    )


def test_cve_src_012_realistic_fixture_detected(ruleset):
    """Realistic fixture with mixed safe/unsafe $authors must trigger CVE-SRC-012."""
    scanner = CVEScanner(ruleset)
    tpl_path = REALISTIC_FIXTURES / "templates" / "frontend" / "pages" / "search.tpl"
    rel = "templates/frontend/pages/search.tpl"
    text = tpl_path.read_text(encoding="utf-8")
    findings = scanner.scan_file(tpl_path, rel, text.encode(), text)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" in rule_ids, (
        f"Expected CVE-SRC-012 from realistic fixture with mixed safe/unsafe authors, got: {rule_ids}"
    )


def test_cve_src_012_suppressed_when_authors_value_escaped(ruleset):
    """CVE-SRC-012 must NOT fire when the value attribute itself uses |escape."""
    scanner = CVEScanner(ruleset)
    tpl = """\
{if $authors}
    <p>{$authors|escape}</p>
{/if}
<form>
    <input type="text" name="authors" value="{$authors|escape}">
</form>
"""
    rel = "templates/frontend/pages/search.tpl"
    findings = scanner.scan_file(Path(rel), rel, tpl.encode(), tpl)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" not in rule_ids, "Should NOT detect when value attribute uses |escape"


# --------------------------------------------------------------------------- #
# CVE-SRC-12229: OJS 2.x template path (templates/search/search.tpl)
# --------------------------------------------------------------------------- #

def test_cve_src_12229_detects_ojs2_template_path(ruleset):
    """CVE-SRC-12229 must detect on the OJS 2.x path templates/search/search.tpl."""
    scanner = CVEScanner(ruleset)
    tpl_path = FIXTURES / "templates" / "search" / "search.tpl"
    rel = "templates/search/search.tpl"
    text = tpl_path.read_text(encoding="utf-8")
    findings = scanner.scan_file(tpl_path, rel, text.encode(), text)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-SRC-12229" in rule_ids, f"Expected CVE-SRC-12229 for OJS 2.x path, got: {rule_ids}"


