"""File path matching with OJS version-aware aliasing."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import List, Optional, Sequence


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


def matches_cve_path(
    file_rel_path: str,
    cve_path_patterns: Sequence[str],
) -> bool:
    """Check if ``file_rel_path`` matches any of the CVE target paths.

    Handles:
    - Exact suffix match (e.g. ``classes/institution/Collector.php``)
    - ``.inc.php`` ↔ ``.php`` aliasing
    - Glob-style ``*`` wildcards
    """
    norm = _normalize(file_rel_path)

    for pattern in cve_path_patterns:
        for alias in path_aliases(pattern):
            nalias = _normalize(alias)
            if norm == nalias or norm.endswith("/" + nalias):
                return True
            # Glob wildcard support (simple)
            if "*" in nalias:
                regex = re.escape(nalias).replace(r"\*", ".*")
                if re.search(regex + "$", norm):
                    return True
    return False
