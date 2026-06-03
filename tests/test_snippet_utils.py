"""Tests for ojs_sast.helpers.snippet_utils."""

from ojs_sast.helpers.snippet_utils import (
    build_code_snippet,
    build_missing_evidence_snippet,
)


# ---- build_code_snippet --------------------------------------------------- #

def _make_text(n: int) -> str:
    """Generate a file with ``n`` numbered lines."""
    return "\n".join(f"line {i}" for i in range(1, n + 1))


def test_long_file_middle_line():
    text = _make_text(20)
    snippet = build_code_snippet(text, 10)
    lines = snippet.strip().splitlines()
    assert len(lines) >= 5
    assert any(">>>" in l and "line 10" in l for l in lines)


def test_match_at_first_line():
    text = _make_text(20)
    snippet = build_code_snippet(text, 1)
    lines = snippet.strip().splitlines()
    assert len(lines) >= 5
    assert ">>>" in lines[0]


def test_match_at_last_line():
    text = _make_text(20)
    snippet = build_code_snippet(text, 20)
    lines = snippet.strip().splitlines()
    assert len(lines) >= 5
    assert any(">>>" in l and "line 20" in l for l in lines)


def test_short_file_three_lines():
    text = _make_text(3)
    snippet = build_code_snippet(text, 2)
    lines = snippet.strip().splitlines()
    assert len(lines) == 3
    assert any(">>>" in l and "line 2" in l for l in lines)


def test_hit_line_marker():
    text = _make_text(10)
    snippet = build_code_snippet(text, 5)
    for line in snippet.splitlines():
        if "line 5" in line:
            assert line.startswith(">>>")
        else:
            assert not line.startswith(">>>")


def test_multiline_hit_range():
    text = _make_text(10)
    snippet = build_code_snippet(text, 3, 5)
    hit_lines = [l for l in snippet.splitlines() if l.startswith(">>>")]
    assert len(hit_lines) == 3  # lines 3, 4, 5


def test_empty_file():
    assert build_code_snippet("", 1) == ""


def test_single_line_file():
    snippet = build_code_snippet("only line", 1)
    assert ">>>" in snippet
    assert "only line" in snippet


def test_crlf_handling():
    text = "line 1\r\nline 2\r\nline 3\r\nline 4\r\nline 5\r\nline 6"
    snippet = build_code_snippet(text, 3)
    lines = snippet.strip().splitlines()
    assert len(lines) >= 5
    assert any(">>>" in l and "line 3" in l for l in lines)


def test_preserves_indentation():
    text = "def foo():\n    x = 1\n    return x\nend\nmore\nmore2"
    snippet = build_code_snippet(text, 2)
    # The indented line should still be present.
    assert "    x = 1" in snippet


def test_invalid_line_number_clamped():
    text = _make_text(5)
    snippet = build_code_snippet(text, 100)
    lines = snippet.strip().splitlines()
    # Should clamp to last line.
    assert len(lines) == 5


def test_line_zero_clamped():
    text = _make_text(5)
    snippet = build_code_snippet(text, 0)
    lines = snippet.strip().splitlines()
    assert len(lines) == 5
    assert ">>>" in lines[0]


# ---- build_missing_evidence_snippet --------------------------------------- #

def test_missing_snippet_with_anchor():
    text = _make_text(10)
    snippet = build_missing_evidence_snippet(text, 3, "my_directive")
    assert ">>> SAST: missing expected directive: my_directive" in snippet
    lines = snippet.strip().splitlines()
    # At least min_lines context + the virtual marker line.
    context_lines = [l for l in lines if ">>> SAST:" not in l]
    assert len(context_lines) >= 5


def test_missing_snippet_without_anchor():
    text = _make_text(10)
    snippet = build_missing_evidence_snippet(text, None, "foo")
    assert ">>> SAST: missing expected directive: foo" in snippet


def test_missing_snippet_empty_file():
    snippet = build_missing_evidence_snippet("", None, "bar")
    assert ">>> SAST: missing expected directive: bar" in snippet


def test_missing_snippet_no_message():
    text = _make_text(5)
    snippet = build_missing_evidence_snippet(text, 1, "")
    assert ">>> SAST: missing expected directive" in snippet
