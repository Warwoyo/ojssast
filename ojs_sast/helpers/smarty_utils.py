"""Smarty template analysis helpers for CVE-specific XSS detection."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Security-aware Smarty output modifiers that neutralize XSS.
_SAFE_MODIFIERS = re.compile(
    r"\|(?:escape|strip_unsafe_html|htmlspecialchars)", re.IGNORECASE
)


def find_smarty_variable(
    template: str,
    variable_pattern: str,
    *,
    require_no_escape: bool = True,
) -> List[Tuple[int, str, str]]:
    """Find Smarty tags matching ``variable_pattern`` in template text.

    Args:
        template: The full .tpl file content.
        variable_pattern: Regex pattern for the variable (e.g. ``r"\\$manualInstructions"``).
        require_no_escape: If True, only return tags lacking |escape or |strip_unsafe_html.

    Returns:
        List of (line_number, full_tag, line_text) tuples.
    """
    results: List[Tuple[int, str, str]] = []
    lines = template.splitlines()

    # Match Smarty tags containing the variable.
    tag_re = re.compile(r"\{[^}]*" + variable_pattern + r"[^}]*\}")

    for i, line in enumerate(lines, 1):
        for m in tag_re.finditer(line):
            tag = m.group(0)
            if require_no_escape and _SAFE_MODIFIERS.search(tag):
                continue
            results.append((i, tag, line.strip()))
    return results


def find_translate_tag(
    template: str,
    key_pattern: Optional[str] = None,
    param_pattern: Optional[str] = None,
) -> List[Tuple[int, str, str]]:
    """Find Smarty {translate ...} tags optionally matching key and param patterns.

    Returns:
        List of (line_number, full_tag, line_text) tuples.
    """
    results: List[Tuple[int, str, str]] = []
    lines = template.splitlines()
    tag_re = re.compile(r"\{translate\b[^}]*\}", re.IGNORECASE)

    for i, line in enumerate(lines, 1):
        for m in tag_re.finditer(line):
            tag = m.group(0)
            if key_pattern and not re.search(key_pattern, tag, re.IGNORECASE):
                continue
            if param_pattern and not re.search(param_pattern, tag, re.IGNORECASE):
                continue
            results.append((i, tag, line.strip()))
    return results


def find_html_attribute_variable(
    template: str,
    attribute_name: str,
    variable_pattern: str,
) -> List[Tuple[int, str, str]]:
    """Find HTML attributes where a Smarty variable is used without |escape.

    E.g. ``value="{$authors}"`` without ``|escape``.

    Returns:
        List of (line_number, full_match, line_text) tuples.
    """
    results: List[Tuple[int, str, str]] = []
    lines = template.splitlines()
    # Match: attribute="...{$variable}..."
    attr_re = re.compile(
        re.escape(attribute_name) + r'\s*=\s*"[^"]*\{' + variable_pattern + r'(?!\|escape)[^}]*\}[^"]*"',
        re.IGNORECASE,
    )

    for i, line in enumerate(lines, 1):
        for m in attr_re.finditer(line):
            results.append((i, m.group(0), line.strip()))
    return results
