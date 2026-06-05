"""File path matching with OJS version-aware aliasing."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import List, Optional, Sequence

# OJS ships PKP library files under these prefixes interchangeably.
_LIB_PKP_PREFIXES = ("lib/pkp/", "pkp-lib/")


def path_aliases(path: str) -> List[str]:
    """Return the given path plus its OJS 3.3↔3.4/3.5 extension alias.

    OJS 3.3 uses ``.inc.php``; OJS 3.4+ uses ``.php``.
    """
    aliases = [path]
    if path.endswith(".inc.php"):
        aliases.append(path[: -len(".inc.php")] + ".php")
    elif path.endswith(".php") and not path.endswith(".inc.php"):
        aliases.append(path[: -len(".php")] + ".inc.php")
    return aliases


def _normalize(p: str) -> str:
    """Strip leading slashes / './' for uniform comparison."""
    return p.lstrip("./").lstrip("/")


def normalize_ojs_path(path: str) -> str:
    """Return a canonical form of an OJS path for alias comparison.

    Strips ``lib/pkp/`` and ``pkp-lib/`` prefixes so that paths like
    ``lib/pkp/classes/statistics/PKPStatisticsHelper.inc.php`` and
    ``classes/statistics/PKPStatisticsHelper.inc.php`` compare equal.
    """
    p = _normalize(path)
    for prefix in _LIB_PKP_PREFIXES:
        if p.startswith(prefix):
            return p[len(prefix):]
    return p


def _file_path_forms(file_rel_path: str) -> List[str]:
    """Expand a scanned file path into all alias forms to test patterns against.

    A pattern only has to match *one* of these forms, so aliasing is applied to
    the file (not the pattern). This keeps regex patterns simple — e.g. a rule
    that lists ``...Collector\\.php$`` matches both the ``.php`` and ``.inc.php``
    file, with or without a ``lib/pkp/`` prefix.
    """
    forms: List[str] = []
    seen: set = set()

    def _add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            forms.append(value)

    for base in (_normalize(file_rel_path), normalize_ojs_path(file_rel_path)):
        for alias in path_aliases(base):
            _add(alias)
            stripped = normalize_ojs_path(alias)
            _add(stripped)
            for prefix in _LIB_PKP_PREFIXES:
                _add(prefix + stripped)
    return forms


def _pattern_matches_path(pattern: str, path: str) -> bool:
    """Match a single ``file_path_pattern`` against one file form.

    The new ruleset expresses paths as anchored regular expressions
    (``classes/institution/Collector\\.php$``, ``.*\\.php$``). We treat the
    pattern as a regex first; legacy literal/glob patterns still work because a
    literal path is a valid (if loose) regex, and ``*`` globs fall back to a
    literal suffix match.
    """
    try:
        if re.search(pattern, path):
            return True
    except re.error:  # pragma: no cover - defensive for malformed patterns
        pass

    npat = _normalize(pattern)
    if path == npat or path.endswith("/" + npat):
        return True
    if "*" in npat:
        glob_regex = re.escape(npat).replace(r"\*", ".*")
        try:
            if re.search(glob_regex + "$", path):
                return True
        except re.error:  # pragma: no cover
            pass
    return False


def matches_cve_path(
    file_rel_path: str,
    cve_path_patterns: Sequence[str],
) -> bool:
    """Check if ``file_rel_path`` matches any of the CVE target paths.

    Handles:
    - Regex ``file_path_patterns`` (e.g. ``classes/.../Collector\\.php$``)
    - Exact / suffix match for legacy literal paths
    - ``.inc.php`` ↔ ``.php`` aliasing
    - Optional ``lib/pkp/`` / ``pkp-lib/`` prefix aliasing
    - Glob-style ``*`` wildcards
    """
    file_forms = _file_path_forms(file_rel_path)
    for pattern in cve_path_patterns:
        for form in file_forms:
            if _pattern_matches_path(pattern, form):
                return True
    return False
