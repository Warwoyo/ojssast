"""Shared rule applicability helpers for version-aware evaluation.

This module separates four distinct concepts that were previously conflated:

* **Loaded rule** — any rule read from the ruleset (``rules_loaded`` stays the
  same for every OJS version).
* **Ground-truth rule** — a rule that belongs to the evaluation dataset
  (``CVE-SRC-*`` and the ground-truth ``OJS-CFG-*`` config checks).
* **Applicable rule** — a ground-truth rule whose ``affected_versions`` cover the
  OJS version currently being scanned.
* **Version FP** — a finding emitted for a ground-truth rule that is *not*
  applicable to the scanned version. It must never be counted as a true
  positive.

``ground_truth: true`` therefore does **not** imply ``applicable: true`` for
every OJS version: the former marks dataset membership, the latter marks
version applicability.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..models import Rule, resolve_rule_metadata
from .version_utils import is_version_affected


def is_rule_applicable_to_version(
    rule: Rule,
    ojs_version: Optional[str],
    *,
    unknown_version_policy: str = "conservative",
    missing_affected_versions_policy: str = "error",
) -> Tuple[bool, str]:
    """Return ``(applicable, reason)`` for ``rule`` against ``ojs_version``.

    * If the rule declares ``params.affected_versions`` (and optionally
      ``params.patched_versions``) the branch-aware :func:`is_version_affected`
      helper decides applicability. Lower bounds (``>=``/``>``) act as an
      AND-required floor so a contiguous config range such as
      ``[">=3.3.0", "<3.6.0"]`` excludes OJS 2.4 while a list of per-branch CVE
      ceilings keeps OR semantics.
    * When ``ojs_version`` is ``None``/empty the ``unknown_version_policy``
      decides: ``"conservative"`` returns applicable ``True`` (do not suppress
      when the version is unknown), ``"exclude"`` returns ``False``.
    * When the rule has no ``affected_versions``:
        - a non ground-truth rule (extension/generic/upload) is reported as not
          applicable to the strict ground-truth scope;
        - a ground-truth rule is a dataset error — with
          ``missing_affected_versions_policy="error"`` it returns
          ``(False, "missing affected_versions ...")`` so tests can catch it,
          while ``"universal"`` treats it as always applicable.
    """
    params = rule.params or {}
    affected = params.get("affected_versions")
    patched = params.get("patched_versions")
    metadata = resolve_rule_metadata(rule.id, params)
    is_ground_truth = metadata.get("ground_truth") is True

    if not affected:
        if is_ground_truth:
            if missing_affected_versions_policy == "universal":
                return True, f"applicable: {rule.id} has no affected_versions (universal policy)"
            return False, f"missing affected_versions for ground-truth rule {rule.id}"
        return False, (
            "not applicable: rule marked extension/generic without affected_versions "
            "(excluded from strict ground-truth scope)"
        )

    if not ojs_version:
        if unknown_version_policy == "exclude":
            return False, "not applicable: unknown OJS version excluded by policy"
        return True, "applicable: unknown OJS version, conservative policy"

    affected_flag, version_reason = is_version_affected(ojs_version, affected, patched)
    spec_text = ",".join(str(s).strip() for s in affected)
    if affected_flag:
        return True, f"applicable: {ojs_version} matches {spec_text}"
    return False, f"not applicable: {ojs_version} outside {spec_text} ({version_reason})"


def get_rule_evaluation_scope_for_version(
    rule: Rule,
    ojs_version: Optional[str],
    *,
    unknown_version_policy: str = "conservative",
    missing_affected_versions_policy: str = "error",
) -> Dict[str, Any]:
    """Return the combined evaluation/applicability metadata for a rule.

    The result extends the ground-truth/scope metadata from
    :func:`resolve_rule_metadata` with version applicability so detectors can
    stamp findings with ``applicable`` / ``applicability_reason`` fields.
    """
    metadata = resolve_rule_metadata(rule.id, rule.params)
    applicable, reason = is_rule_applicable_to_version(
        rule,
        ojs_version,
        unknown_version_policy=unknown_version_policy,
        missing_affected_versions_policy=missing_affected_versions_policy,
    )
    return {
        "ground_truth": metadata["ground_truth"],
        "evaluation_scope": metadata["evaluation_scope"],
        "applicable": applicable,
        "applicability_reason": reason,
    }
