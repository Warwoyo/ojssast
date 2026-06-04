"""OJS version parsing and comparison utilities."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse an OJS version string like '3.3.0-13' into a comparable tuple.

    Returns e.g. (3, 3, 0, 13). Handles formats:
      - '3.3.0-13'  → (3, 3, 0, 13)
      - '3.3.0.13'  → (3, 3, 0, 13)
      - '3.4.0'     → (3, 4, 0, 0)
      - 'v3.4.0-7'  → (3, 4, 0, 7)
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


def parse_version_raw(version_str: str) -> Tuple[int, ...]:
    """Parse an OJS version string like '3.3.0-13' into a raw tuple without padding."""
    if not version_str:
        return ()
    version_str = version_str.strip().lstrip("v").strip()
    parts = re.split(r"[.\-]", version_str)
    result: List[int] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def version_branch(v: Tuple[int, ...]) -> Tuple[int, int, int]:
    """Return the major/minor/patch branch for a parsed version tuple."""
    padded = v + (0, 0, 0)
    return padded[0], padded[1], padded[2]


def _normalize_spec_version(spec: str, operator: str) -> str:
    return spec[len(operator) :].strip()


def _matches_affected_spec(detected: str, det: Tuple[int, ...], spec: str) -> Optional[str]:
    spec = spec.strip()
    raw_det = parse_version_raw(detected)

    if spec.startswith("<="):
        spec_version = _normalize_spec_version(spec, "<=")
        bound = parse_version(spec_version)
        if det <= bound:
            return f"detected {detected} <= {spec_version}"
    elif spec.startswith("<"):
        spec_version = _normalize_spec_version(spec, "<")
        bound = parse_version(spec_version)
        if det < bound:
            return f"detected {detected} < {spec_version}"
    elif spec.startswith(">="):
        spec_version = _normalize_spec_version(spec, ">=")
        bound = parse_version(spec_version)
        if det >= bound:
            return f"detected {detected} >= {spec_version}"
    elif spec.startswith(">"):
        spec_version = _normalize_spec_version(spec, ">")
        bound = parse_version(spec_version)
        if det > bound:
            return f"detected {detected} > {spec_version}"
    elif spec.startswith("=="):
        spec_version = _normalize_spec_version(spec, "==")
        exact = parse_version(spec_version)
        if det == exact:
            return f"detected {detected} == {spec_version}"
    elif spec.startswith("="):
        spec_version = _normalize_spec_version(spec, "=")
        exact = parse_version(spec_version)
        if det == exact:
            return f"detected {detected} == {spec_version}"
    else:
        # Raw prefix match: "3.3.0" matches "3.3.0-13", but not "3.4.0-1".
        raw_spec = parse_version_raw(spec)
        if raw_spec and raw_det[: len(raw_spec)] == raw_spec:
            return f"detected {detected} matches prefix {spec}"

    return None


def _ignored_patched_specs_reason(ignored_specs: List[str]) -> str:
    if not ignored_specs:
        return ""
    return f"; ignored patched specs from other branches: {', '.join(ignored_specs)}"


def version_matches_spec(detected: str, spec: str) -> bool:
    """Return True if ``detected`` satisfies a single version ``spec`` bound.

    Supports the same operators as :func:`is_version_affected`
    (``>=``, ``>``, ``<=``, ``<``, ``==``, ``=`` and a bare prefix).
    """
    det = parse_version(detected)
    return _matches_affected_spec(detected, det, spec) is not None


def _is_lower_bound(spec: str) -> bool:
    return spec.strip().startswith((">=", ">"))


def is_version_affected(
    detected: Optional[str],
    affected_specs: Optional[List[str]],
    patched_specs: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Check whether ``detected`` falls within affected version ranges.

    ``affected_specs`` items are strings like ``"<=3.4.0-9"``, ``"<3.3.0-16"``
    or ``"3.3.0"`` (raw prefix match).

    Returns (is_affected: bool, reason: str).
    If ``detected`` is None/empty, returns (True, "OJS version unknown; assuming potentially affected").
    """
    if not detected:
        return True, "OJS version unknown; assuming potentially affected"

    det = parse_version(detected)
    det_branch = version_branch(det)

    affected_match_reasons: List[str] = []
    if affected_specs:
        # Lower bounds (``>=`` / ``>``) are AND-required: they define the floor of
        # a contiguous affected range (e.g. ``[">=3.3.0", "<3.6.0"]`` reads as
        # ``>=3.3.0`` *and* ``<3.6.0``). Upper/exact/prefix bounds keep OR
        # semantics so a list of per-branch ceilings
        # (``["<=3.3.0-21", "<=3.4.0-9"]``) still matches any affected branch.
        # Rules without a lower bound behave exactly as before (backward compatible).
        lower_specs = [s for s in affected_specs if _is_lower_bound(s)]
        other_specs = [s for s in affected_specs if not _is_lower_bound(s)]

        lower_ok = all(
            _matches_affected_spec(detected, det, spec) is not None for spec in lower_specs
        )
        if other_specs:
            for spec in other_specs:
                match_reason = _matches_affected_spec(detected, det, spec)
                if match_reason:
                    affected_match_reasons.append(match_reason)
            other_ok = bool(affected_match_reasons)
        else:
            other_ok = True
            affected_match_reasons.append("no upper-bound constraints")

        if lower_specs:
            affected_match_reasons.append(f"satisfies floor {', '.join(lower_specs)}")
        matches_affected = lower_ok and other_ok
    else:
        matches_affected = True
        affected_match_reasons.append("no affected-version constraints defined")

    if not matches_affected:
        return False, f"detected {detected} is not in affected ranges {affected_specs}"

    same_branch_patches: List[Tuple[str, Tuple[int, ...]]] = []
    other_branch_patches: List[str] = []
    if patched_specs:
        for spec in patched_specs:
            spec_clean = spec.strip()
            pv = parse_version(spec_clean)
            if version_branch(pv) == det_branch:
                same_branch_patches.append((spec_clean, pv))
            else:
                other_branch_patches.append(spec_clean)

    ignored_reason = _ignored_patched_specs_reason(other_branch_patches)
    if same_branch_patches:
        patch_spec, patch_version = min(same_branch_patches, key=lambda item: item[1])
        if det >= patch_version:
            return False, f"detected {detected} >= patched {patch_spec} on same branch{ignored_reason}"
        return True, (
            f"detected {detected} matches affected range and is below patched {patch_spec} "
            f"on same branch{ignored_reason}"
        )

    return True, f"detected {detected} matches affected range; no same-branch patched version defined{ignored_reason}"
