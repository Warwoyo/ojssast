"""Regression tests for CVE-oriented source matching helpers."""

from ojs_sast.helpers.php_utils import find_pattern_span


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
