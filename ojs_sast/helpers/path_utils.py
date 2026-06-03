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


def _path_candidates(path: str) -> List[str]:
    """Expand a single path pattern into all alias variants to try."""
    candidates: List[str] = []
    # Original + extension alias
    for ext_alias in path_aliases(path):
        candidates.append(ext_alias)
        # Also try with / without lib/pkp prefix
        norm = normalize_ojs_path(ext_alias)
        if norm != _normalize(ext_alias):
            candidates.append(norm)
        for prefix in _LIB_PKP_PREFIXES:
            candidates.append(prefix + norm)
    # Deduplicate while preserving order
    seen: set = set()
    result: List[str] = []
    for c in candidates:
        nc = _normalize(c)
        if nc not in seen:
            seen.add(nc)
            result.append(c)
    return result


def matches_cve_path(
    file_rel_path: str,
    cve_path_patterns: Sequence[str],
) -> bool:
    """Check if ``file_rel_path`` matches any of the CVE target paths.

    Handles:
    - Exact suffix match (e.g. ``classes/institution/Collector.php``)
    - ``.inc.php`` ↔ ``.php`` aliasing
    - Optional ``lib/pkp/`` / ``pkp-lib/`` prefix aliasing
    - Glob-style ``*`` wildcards
    """
    norm = _normalize(file_rel_path)
    norm_no_prefix = normalize_ojs_path(file_rel_path)

    for pattern in cve_path_patterns:
        for candidate in _path_candidates(pattern):
            ncandidate = _normalize(candidate)
            # Exact suffix match (handles leading path components from root)
            if norm == ncandidate or norm.endswith("/" + ncandidate):
                return True
            # Also try matching normalised form against normalised candidate
            if norm_no_prefix == ncandidate or norm_no_prefix.endswith("/" + ncandidate):
                return True
            # Glob wildcard support (simple)
            if "*" in ncandidate:
                regex = re.escape(ncandidate).replace(r"\*", ".*")
                if re.search(regex + "$", norm) or re.search(regex + "$", norm_no_prefix):
                    return True
    return False
