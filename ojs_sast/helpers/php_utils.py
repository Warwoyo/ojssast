"""PHP source analysis helpers (regex-based, no AST required)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class PatternMatch:
    pattern: str
    start: int
    end: int
    line_start: int
    line_end: int
    snippet: str | None = None


def find_pattern_span(
    source: str,
    pattern: str,
    flags: int = re.IGNORECASE | re.MULTILINE | re.DOTALL,
) -> Optional[PatternMatch]:
    """Find the first regex match and return its span, line range, and snippet."""
    match = re.search(pattern, source, flags)
    if match is None:
        return None

    return PatternMatch(
        pattern=pattern,
        start=match.start(),
        end=match.end(),
        line_start=source.count("\n", 0, match.start()) + 1,
        line_end=source.count("\n", 0, match.end()) + 1,
        snippet=match.group(0).strip(),
    )


def extract_function_body(source: str, function_name: str) -> Optional[str]:
    """Extract the body of a PHP function/method by name (regex heuristic).

    Returns the full text from function signature to its closing brace,
    or None if not found.  Works for class methods and top-level functions.
    """
    # Match: function <name>(...) { ... }
    pattern = re.compile(
        r"(?:public\s+|protected\s+|private\s+|static\s+)*"
        r"function\s+" + re.escape(function_name) + r"\s*\(",
        re.IGNORECASE,
    )
    m = pattern.search(source)
    if m is None:
        return None

    start = m.start()
    # Find the opening brace.
    brace_pos = source.find("{", m.end())
    if brace_pos == -1:
        return None

    depth = 0
    i = brace_pos
    while i < len(source):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        elif ch == "'" or ch == '"':
            # Skip string literals.
            q = ch
            i += 1
            while i < len(source) and source[i] != q:
                if source[i] == "\\":
                    i += 1
                i += 1
        elif ch == "/" and i + 1 < len(source):
            if source[i + 1] == "/":
                # Skip line comment.
                nl = source.find("\n", i + 2)
                i = nl if nl != -1 else len(source)
                continue
            elif source[i + 1] == "*":
                end = source.find("*/", i + 2)
                i = end + 1 if end != -1 else len(source)
                continue
        i += 1
    return None


def extract_class_body(source: str, class_name: str) -> Optional[str]:
    """Extract the body of a PHP class by name (regex heuristic)."""
    pattern = re.compile(
        r"class\s+" + re.escape(class_name) + r"\b[^{]*\{",
        re.IGNORECASE,
    )
    m = pattern.search(source)
    if m is None:
        return None

    start = m.start()
    brace_pos = m.end() - 1  # The '{' at end of match.
    depth = 0
    i = brace_pos
    while i < len(source):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        elif ch == "'" or ch == '"':
            q = ch
            i += 1
            while i < len(source) and source[i] != q:
                if source[i] == "\\":
                    i += 1
                i += 1
        i += 1
    return None


def has_pattern_in_function(
    source: str, function_name: str, pattern: str, flags: int = re.IGNORECASE
) -> bool:
    """Check if ``pattern`` (regex) appears inside ``function_name``'s body."""
    body = extract_function_body(source, function_name)
    if body is None:
        return False
    return bool(re.search(pattern, body, flags))


def find_pattern_line(source: str, pattern: str, flags: int = 0) -> Optional[Tuple[int, str]]:
    """Find the first line matching ``pattern`` and return (line_number, line_text)."""
    for i, line in enumerate(source.splitlines(), 1):
        if re.search(pattern, line, flags):
            return i, line.strip()
    return None


def find_all_pattern_lines(
    source: str, pattern: str, flags: int = 0
) -> List[Tuple[int, str]]:
    """Find all lines matching ``pattern``, returning [(line_number, line_text), ...]."""
    results = []
    for i, line in enumerate(source.splitlines(), 1):
        if re.search(pattern, line, flags):
            results.append((i, line.strip()))
    return results


def find_all_pattern_spans(
    source: str,
    pattern: str,
    flags: int = re.IGNORECASE | re.MULTILINE | re.DOTALL,
) -> List[PatternMatch]:
    """Find ALL regex matches and return their span, line range, and snippet."""
    results: List[PatternMatch] = []
    for match in re.finditer(pattern, source, flags):
        results.append(PatternMatch(
            pattern=pattern,
            start=match.start(),
            end=match.end(),
            line_start=source.count("\n", 0, match.start()) + 1,
            line_end=source.count("\n", 0, match.end()) + 1,
            snippet=match.group(0).strip(),
        ))
    return results


def find_request_variables(source: str, param_names: set) -> dict:
    """Find PHP variables assigned from getUserVar() for given parameter names.

    Returns {variable_name: line_number}.  Only the first assignment per variable
    is recorded.  Supports the common OJS request patterns:
      $var = $request->getUserVar('param')
      $var = Request::getUserVar('param')
      $var = $this->getRequest()->getUserVar('param')
    """
    results: dict = {}
    for param in param_names:
        pat = re.compile(
            r"(\$\w+)\s*=\s*(?:[^;\n]*?)getUserVar\s*\(\s*['\"]"
            + re.escape(param) + r"['\"]",
            re.IGNORECASE,
        )
        for i, line in enumerate(source.splitlines(), 1):
            m = pat.search(line)
            if m:
                varname = m.group(1)
                if varname not in results:
                    results[varname] = i
    return results


def find_unserialize_sinks(source: str, variables: set) -> List[PatternMatch]:
    """Find unserialize() calls whose first argument is one of *variables*.

    Detects:
      unserialize($var)
      @unserialize($var)
      unserialize(base64_decode($var))
    """
    results: List[PatternMatch] = []
    for var in variables:
        var_esc = re.escape(var)
        pat = rf"@?unserialize\s*\(\s*(?:base64_decode\s*\(\s*)?{var_esc}\b"
        for m in re.finditer(pat, source, re.IGNORECASE):
            results.append(PatternMatch(
                pattern=pat,
                start=m.start(),
                end=m.end(),
                line_start=source.count("\n", 0, m.start()) + 1,
                line_end=source.count("\n", 0, m.end()) + 1,
                snippet=source[m.start():m.end()].strip(),
            ))
    return results
