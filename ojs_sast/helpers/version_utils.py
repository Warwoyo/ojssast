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


# An operator bound parsed into ``(operator, parsed_version)``.
_Bound = Tuple[str, Tuple[int, ...]]


def _spec_bound(spec: str) -> Optional[_Bound]:
    """Parse an operator spec (``>=``/``>``/``<=``/``<``) into ``(op, version)``.

    Returns ``None`` for bare prefix/exact specs such as ``"3.3.0"`` so the caller
    can evaluate them independently.
    """
    spec = spec.strip()
    for op in (">=", "<=", ">", "<"):
        if spec.startswith(op):
            return op, parse_version(_normalize_spec_version(spec, op))
    return None


def _in_range(det: Tuple[int, ...], lo: Optional[_Bound], hi: Optional[_Bound]) -> bool:
    """Return True if ``det`` satisfies a single ``[lo, hi]`` range (AND of bounds).

    A missing bound is treated as unbounded on that side.
    """
    if lo is not None:
        op, v = lo
        if op == ">=" and not det >= v:
            return False
        if op == ">" and not det > v:
            return False
    if hi is not None:
        op, v = hi
        if op == "<=" and not det <= v:
            return False
        if op == "<" and not det < v:
            return False
    return True


def _evaluate_affected_specs(
    detected: str, det: Tuple[int, ...], affected_specs: List[str]
) -> Tuple[bool, str]:
    """Interpret a flat affected-version spec list as a UNION of ``[floor, ceiling]``
    ranges (disjunctive normal form).

    Each ceiling (``<`` / ``<=``) closes a range opened by the most recent floor
    (``>=`` / ``>``); a floor with no following ceiling stays open-ended. This
    makes a multi-branch list such as ``['<3.3.0-16', '>=3.4.0', '<3.4.0-4']`` read
    as ``(<3.3.0-16) OR (>=3.4.0 AND <3.4.0-4)`` instead of AND-ing every floor —
    the latter previously excluded the whole 3.3.x branch as soon as a later branch
    contributed its own ``>=`` floor. A single floor+ceiling pair (e.g. a contiguous
    config range ``['>=3.3.0', '<3.6.0']``) collapses to one range, preserving the
    earlier behaviour. Bare prefix/exact specs (``'3.3.0'``) are evaluated
    independently with OR semantics.
    """
    ranges: List[Tuple[Optional[_Bound], Optional[_Bound]]] = []
    standalone: List[str] = []
    cur_floor: Optional[_Bound] = None

    for spec in affected_specs:
        bound = _spec_bound(spec)
        if bound is None:
            standalone.append(spec.strip())
            continue
        if bound[0] in (">=", ">"):
            if cur_floor is not None:
                # Two floors in a row: the previous one had no ceiling (open range).
                ranges.append((cur_floor, None))
            cur_floor = bound
        else:  # "<" / "<="
            ranges.append((cur_floor, bound))
            cur_floor = None
    if cur_floor is not None:
        ranges.append((cur_floor, None))

    for lo, hi in ranges:
        if _in_range(det, lo, hi):
            return True, f"detected {detected} matches affected range in {affected_specs}"

    for spec in standalone:
        reason = _matches_affected_spec(detected, det, spec)
        if reason:
            return True, reason

    return False, f"detected {detected} is not in affected ranges {affected_specs}"


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

    # Interpret ``affected_specs`` as a union of per-branch [floor, ceiling] ranges
    # (see :func:`_evaluate_affected_specs`). This keeps contiguous single-range
    # specs working while correctly handling multi-branch lists, which the previous
    # "all floors AND-required" rule mishandled (a later branch's ``>=`` floor would
    # wrongly exclude every earlier affected branch).
    if affected_specs:
        matches_affected, affected_reason = _evaluate_affected_specs(detected, det, affected_specs)
    else:
        matches_affected, affected_reason = True, "no affected-version constraints defined"

    if not matches_affected:
        return False, affected_reason

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
