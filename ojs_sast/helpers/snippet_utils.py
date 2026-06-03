"""Reusable helpers for building multi-line code snippets with line markers.

Every SAST finding should present at least 5 lines of context (when the file
is long enough) so the reviewer can understand the surrounding code.  Lines
that are directly flagged by the scanner are prefixed with ``>>>`` while
context lines get a plain indent.  Line numbers are right-aligned for
readability.

Two entry-points cover the common cases:

* :func:`build_code_snippet` — highlight one or more *existing* lines.
* :func:`build_missing_evidence_snippet` — show context and append a virtual
  annotation line for a directive/block that is *absent* from the file.
"""

from __future__ import annotations

from typing import Optional


def build_code_snippet(
    text: str,
    line_start: int,
    line_end: Optional[int] = None,
    *,
    min_lines: int = 5,
    context_before: int = 2,
    context_after: int = 2,
) -> str:
    """Build a multi-line code snippet with hit-line markers.

    Parameters
    ----------
    text:
        Full file content (may use ``\\n`` or ``\\r\\n``).
    line_start:
        First hit line (1-indexed).
    line_end:
        Last hit line (1-indexed, inclusive).  Defaults to *line_start*.
    min_lines:
        Minimum number of output lines (if the file is long enough).
    context_before / context_after:
        Desired lines of context around the hit range.

    Returns
    -------
    str
        Formatted snippet.  Empty string when *text* is empty.
    """
    if not text:
        return ""

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    total = len(lines)
    if total == 0:
        return ""

    # Clamp hit range into valid bounds.
    line_start = max(1, min(line_start, total))
    if line_end is None:
        line_end = line_start
    line_end = max(line_start, min(line_end, total))

    # Desired window.
    win_start = line_start - context_before
    win_end = line_end + context_after

    # Enforce minimum lines.
    current_span = win_end - win_start + 1
    if current_span < min_lines and total >= min_lines:
        deficit = min_lines - current_span
        # Try to expand equally in both directions.
        expand_before = deficit // 2
        expand_after = deficit - expand_before
        win_start -= expand_before
        win_end += expand_after

    # Clamp to file boundaries, then re-expand the other direction if needed.
    if win_start < 1:
        win_end += 1 - win_start
        win_start = 1
    if win_end > total:
        win_start -= win_end - total
        win_end = total
    win_start = max(1, win_start)
    win_end = min(total, win_end)

    return _format_lines(lines, win_start, win_end, line_start, line_end)


def build_missing_evidence_snippet(
    text: str,
    anchor_line: Optional[int] = None,
    message: str = "",
    *,
    min_lines: int = 5,
) -> str:
    """Build a snippet for a finding about a *missing* directive.

    Shows ``min_lines`` of context from the file and appends a clearly-marked
    virtual annotation line.

    Parameters
    ----------
    text:
        Full file content.
    anchor_line:
        Optional reference line (e.g. the ``[section]`` header).  If ``None``,
        context is taken from the start of the file.
    message:
        Human-readable description (e.g. ``"allowed_hosts"``).
    min_lines:
        Minimum context lines to show from the file.
    """
    if not text:
        marker = f">>> SAST: missing expected directive: {message}" if message else ">>> SAST: missing expected directive"
        return marker

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    total = len(lines)

    if anchor_line is None or anchor_line < 1 or anchor_line > total:
        # Default to the beginning of the file.
        win_start = 1
        win_end = min(total, min_lines)
    else:
        half = min_lines // 2
        win_start = max(1, anchor_line - half)
        win_end = win_start + min_lines - 1
        if win_end > total:
            win_start = max(1, total - min_lines + 1)
            win_end = total

    # No hit line — all lines are context.
    out = _format_lines(lines, win_start, win_end, hit_start=0, hit_end=0)
    marker = f">>> SAST: missing expected directive: {message}" if message else ">>> SAST: missing expected directive"
    return out + "\n" + marker


# ---- internal helpers -------------------------------------------------------

def _format_lines(
    lines: list[str],
    win_start: int,
    win_end: int,
    hit_start: int,
    hit_end: int,
) -> str:
    """Format a window of lines with numbers and ``>>>`` markers."""
    width = len(str(win_end))
    result: list[str] = []
    for i in range(win_start, win_end + 1):
        num = str(i).rjust(width)
        content = lines[i - 1]  # 0-indexed
        if hit_start <= i <= hit_end:
            result.append(f">>> {num} | {content}")
        else:
            result.append(f"    {num} | {content}")
    return "\n".join(result)
