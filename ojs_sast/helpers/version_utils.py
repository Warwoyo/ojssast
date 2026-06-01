"""OJS version parsing and comparison utilities."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse an OJS version string like '3.3.0-13' into a comparable tuple.

    Returns e.g. (3, 3, 0, 13). Handles formats:
      - '3.3.0-13'  → (3, 3, 0, 13)
      - '3.4.0'     → (3, 4, 0, 0)
      - '3.5.0-2'   → (3, 5, 0, 2)
    """
    if not version_str:
        return (0,)
    # Strip any leading 'v' or whitespace.
    version_str = version_str.strip().lstrip("v").strip()
    # Split on '.' and '-'
    parts = re.split(r"[.\-]", version_str)
    result: List[int] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    # Ensure at least 4 components (major.minor.patch.build).
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def is_version_affected(
    detected: Optional[str],
    affected_specs: Optional[List[str]],
    patched_specs: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Check whether ``detected`` falls within affected version ranges.

    ``affected_specs`` items are strings like ``"<=3.4.0-9"``, ``"<3.3.0-16"``
    or ``"3.3.0"`` (exact match prefix).

    Returns (is_affected: bool, reason: str).
    If ``detected`` is None/empty, returns (True, "version unknown ...").
    """
    if not detected:
        return True, "OJS version unknown; assuming potentially affected"

    det = parse_version(detected)

    if not affected_specs:
        return True, "no affected-version constraints defined"

    # Check patched versions first — if detected matches a patched version, safe.
    if patched_specs:
        for spec in patched_specs:
            spec_clean = spec.strip()
            pv = parse_version(spec_clean)
            if det >= pv:
                return False, f"detected {detected} >= patched {spec_clean}"

    for spec in affected_specs:
        spec = spec.strip()
        if spec.startswith("<="):
            bound = parse_version(spec[2:])
            if det <= bound:
                return True, f"detected {detected} <= {spec[2:]}"
        elif spec.startswith("<"):
            bound = parse_version(spec[1:])
            if det < bound:
                return True, f"detected {detected} < {spec[1:]}"
        elif spec.startswith(">="):
            bound = parse_version(spec[2:])
            if det >= bound:
                return True, f"detected {detected} >= {spec[2:]}"
        elif spec.startswith(">"):
            bound = parse_version(spec[1:])
            if det > bound:
                return True, f"detected {detected} > {spec[1:]}"
        elif spec.startswith("==") or spec.startswith("="):
            exact = parse_version(spec.lstrip("="))
            if det == exact:
                return True, f"detected {detected} == {spec.lstrip('=')}"
        else:
            # Prefix match: "3.3.0" matches any 3.3.0-x
            pv = parse_version(spec)
            if det[:len(pv)] == pv[:len(det)]:
                return True, f"detected {detected} matches prefix {spec}"

    return False, f"detected {detected} is not in affected ranges {affected_specs}"
