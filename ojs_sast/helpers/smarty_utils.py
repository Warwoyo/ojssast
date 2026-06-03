"""Smarty template analysis helpers for CVE-specific XSS detection."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Security-aware Smarty output modifiers that neutralize XSS.
_SAFE_MODIFIERS = re.compile(
    r"\|(?:escape|strip_unsafe_html|htmlspecialchars)", re.IGNORECASE
)

# Matches |escape modifier (optionally with :'html' or :"html")
_ESCAPE_MODIFIER = re.compile(
    r"\|\s*escape(?:\s*:\s*['\"]?html['\"]?)?", re.IGNORECASE
)


def smarty_expression_is_escaped(expr: str) -> bool:
    """Return True if a Smarty expression contains a safe |escape modifier."""
    return bool(_ESCAPE_MODIFIER.search(expr))


def find_smarty_variable(
    template: str,
    variable_pattern: str,
    *,
    require_no_escape: bool = True,
) -> List[Tuple[int, str, str]]:
    """Find Smarty tags matching ``variable_pattern`` in template text.

    Multiline-aware: uses DOTALL so tags spanning multiple lines are handled.

    Args:
        template: The full .tpl file content.
        variable_pattern: Regex for the variable (e.g. ``r"\\$manualInstructions"``).
        require_no_escape: If True, skip tags that already contain |escape.

    Returns:
        List of (line_number, full_tag, line_text) tuples.
    """
    results: List[Tuple[int, str, str]] = []
    tag_re = re.compile(
        r"\{[^{}]*" + variable_pattern + r"[^{}]*\}",
        re.DOTALL | re.IGNORECASE,
    )
    for m in tag_re.finditer(template):
        tag = m.group(0)
        if require_no_escape and _SAFE_MODIFIERS.search(tag):
            continue
        line_start = template.count("\n", 0, m.start()) + 1
        line_text = tag.replace("\n", " ").strip()
        results.append((line_start, tag, line_text))
    return results


def find_translate_tag(
    template: str,
    key_pattern: Optional[str] = None,
    param_pattern: Optional[str] = None,
) -> List[Tuple[int, str, str]]:
    """Find Smarty {translate ...} tags — multiline aware.

    Returns:
        List of (line_number, full_tag, line_text) tuples.
    """
    results: List[Tuple[int, str, str]] = []
    tag_re = re.compile(r"\{translate\b[^{}]*\}", re.IGNORECASE | re.DOTALL)

    for m in tag_re.finditer(template):
        tag = m.group(0)
        if key_pattern and not re.search(key_pattern, tag, re.IGNORECASE | re.DOTALL):
            continue
        if param_pattern and not re.search(param_pattern, tag, re.IGNORECASE | re.DOTALL):
            continue
        line_start = template.count("\n", 0, m.start()) + 1
        line_text = tag.replace("\n", " ").strip()
        results.append((line_start, tag, line_text))
    return results


def find_html_attribute_variable(
    template: str,
    attribute_name: str,
    variable_pattern: str,
) -> List[Tuple[int, str, str]]:
    """Find HTML input tags where a Smarty variable appears without |escape.

    Multiline-aware: extracts ``<input ...>`` blocks spanning multiple lines.

    Returns:
        List of (line_number, full_match, line_text) tuples.
    """
    results: List[Tuple[int, str, str]] = []

    # Match entire <input ...> blocks (may span lines).
    input_tag_re = re.compile(r"<input\b[^>]*>", re.IGNORECASE | re.DOTALL)

    # Within a tag block: attribute="{$variable}" without |escape.
    attr_val_re = re.compile(
        re.escape(attribute_name)
        + r'\s*=\s*["\']?\s*\{' + variable_pattern
        + r'(?!\s*\|\s*escape)[^}]*\}',
        re.IGNORECASE | re.DOTALL,
    )

    for tag_m in input_tag_re.finditer(template):
        tag = tag_m.group(0)
        if attr_val_re.search(tag):
            line_start = template.count("\n", 0, tag_m.start()) + 1
            line_text = tag.replace("\n", " ").strip()
            results.append((line_start, tag, line_text))
    return results
