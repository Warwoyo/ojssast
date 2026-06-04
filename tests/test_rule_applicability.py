"""Tests for version-aware rule applicability.

``affected_versions`` controls version applicability, not rule loading: a rule
may be loaded (rules_loaded stays constant) yet not applicable to the scanned
OJS version.
"""

import pytest

from ojs_sast.helpers.rule_applicability import (
    get_rule_evaluation_scope_for_version,
    is_rule_applicable_to_version,
)
from ojs_sast.models import Rule, Severity

# Ground-truth config id groups by their affected_versions tier.
CONFIG_GT_IDS = (
    {f"OJS-CFG-GEN-{i:03d}" for i in range(1, 12)}
    | {f"OJS-CFG-SEC-{i:03d}" for i in range(1, 15)}
    | {f"OJS-CFG-DB-{i:03d}" for i in range(1, 4)}
    | {f"OJS-CFG-FILE-{i:03d}" for i in range(1, 5)}
    | {"OJS-CFG-EMAIL-001", "OJS-CFG-EMAIL-002", "OJS-CFG-CAP-001"}
    | {f"OJS-CFG-DBG-{i:03d}" for i in range(1, 5)}
)
CVE_GT_IDS = {f"CVE-SRC-{i:03d}" for i in range(1, 13)}


@pytest.fixture(scope="module")
def rs():
    from ojs_sast.ruleset.loader import load_ruleset

    return load_ruleset()


# --------------------------------------------------------------------------- #
# Config rule applicability (continuous ">=X,<3.6.0" ranges)
# --------------------------------------------------------------------------- #
def test_config_rule_33_34_35_applicable_to_33(rs):
    # OJS-CFG-SEC-001 (force_ssl) is affected on OJS 3.3, 3.4, 3.5.
    ok, reason = is_rule_applicable_to_version(rs.get("OJS-CFG-SEC-001"), "3.3.0-13")
    assert ok is True
    assert "3.3.0-13 matches" in reason


def test_config_rule_33_34_35_applicable_to_34(rs):
    ok, _ = is_rule_applicable_to_version(rs.get("OJS-CFG-SEC-001"), "3.4.0-7")
    assert ok is True


def test_config_rule_33_34_35_not_applicable_to_24(rs):
    ok, reason = is_rule_applicable_to_version(rs.get("OJS-CFG-SEC-001"), "2.4.7-1")
    assert ok is False
    assert "outside" in reason


def test_config_rule_34_35_not_applicable_to_33(rs):
    # OJS-CFG-GEN-007 (session_samesite) and CAP-001 are affected on OJS 3.4, 3.5 only.
    for rid in ("OJS-CFG-GEN-007", "OJS-CFG-CAP-001"):
        ok, _ = is_rule_applicable_to_version(rs.get(rid), "3.3.0-13")
        assert ok is False, rid


def test_config_rule_34_35_applicable_to_34(rs):
    for rid in ("OJS-CFG-GEN-007", "OJS-CFG-CAP-001"):
        ok, _ = is_rule_applicable_to_version(rs.get(rid), "3.4.0-7")
        assert ok is True, rid


def test_config_rule_35_not_applicable_to_34(rs):
    # OJS 3.5-only directives.
    for rid in ("OJS-CFG-SEC-010", "OJS-CFG-SEC-011", "OJS-CFG-SEC-012",
                "OJS-CFG-SEC-013", "OJS-CFG-DB-003"):
        ok, _ = is_rule_applicable_to_version(rs.get(rid), "3.4.0-7")
        assert ok is False, rid


def test_config_rule_35_applicable_to_35(rs):
    for rid in ("OJS-CFG-SEC-010", "OJS-CFG-SEC-013", "OJS-CFG-DB-003"):
        ok, _ = is_rule_applicable_to_version(rs.get(rid), "3.5.0-1")
        assert ok is True, rid


def test_config_rule_312_tier_applicable_to_24_is_false(rs):
    # OJS-CFG-GEN-003 (allowed_hosts) is OJS 3.1.2, 3.3, 3.4, 3.5 — still not OJS 2.4.
    assert is_rule_applicable_to_version(rs.get("OJS-CFG-GEN-003"), "2.4.7-1")[0] is False
    assert is_rule_applicable_to_version(rs.get("OJS-CFG-GEN-003"), "3.3.0-13")[0] is True


def test_all_config_gt_rules_have_affected_versions(rs):
    """Every ground-truth config rule MUST declare affected_versions."""
    missing = [rid for rid in CONFIG_GT_IDS if not rs.get(rid).params.get("affected_versions")]
    assert missing == [], f"GT config rules missing affected_versions: {missing}"


def test_all_cve_gt_rules_have_affected_versions(rs):
    missing = [rid for rid in CVE_GT_IDS if not rs.get(rid).params.get("affected_versions")]
    assert missing == [], f"CVE GT rules missing affected_versions: {missing}"


# --------------------------------------------------------------------------- #
# CVE rule applicability (branch-aware per-branch ceilings + patched versions)
# --------------------------------------------------------------------------- #
def test_cve_affected_versions_branch_aware(rs):
    # CVE-SRC-002: affected <=3.3.0-21, <=3.4.0-9, <=3.5.0-1; patched per branch.
    rule = rs.get("CVE-SRC-002")
    assert is_rule_applicable_to_version(rule, "3.3.0-13")[0] is True
    assert is_rule_applicable_to_version(rule, "3.4.0-7")[0] is True
    # Patched build on the same branch is no longer affected (branch-aware).
    assert is_rule_applicable_to_version(rule, "3.4.0-10")[0] is False
    # OJS 2.4 is below the 3.3 floor.
    assert is_rule_applicable_to_version(rule, "2.4.7-1")[0] is False


def test_cve_001_not_applicable_to_33_but_applicable_to_34(rs):
    # CVE-SRC-001 query-builder code "does not exist in 3.3.0".
    rule = rs.get("CVE-SRC-001")
    assert is_rule_applicable_to_version(rule, "3.3.0-13")[0] is False
    assert is_rule_applicable_to_version(rule, "3.4.0-7")[0] is True


def test_cve_old_vulns_reach_ojs24(rs):
    # CVE-SRC-010 / CVE-SRC-011 explicitly affect older 2.x.
    assert is_rule_applicable_to_version(rs.get("CVE-SRC-010"), "2.4.7-1")[0] is True
    assert is_rule_applicable_to_version(rs.get("CVE-SRC-011"), "2.4.7-1")[0] is True
    # CVE-SRC-012 ground truth is "3.0.0 to 3.1.1-1" — excludes 2.4.
    assert is_rule_applicable_to_version(rs.get("CVE-SRC-012"), "2.4.7-1")[0] is False


# --------------------------------------------------------------------------- #
# Unknown version + missing metadata policies
# --------------------------------------------------------------------------- #
def test_unknown_version_conservative_is_applicable(rs):
    ok, reason = is_rule_applicable_to_version(rs.get("OJS-CFG-SEC-001"), None)
    assert ok is True
    assert "conservative" in reason


def test_unknown_version_exclude_policy(rs):
    ok, _ = is_rule_applicable_to_version(
        rs.get("OJS-CFG-SEC-001"), None, unknown_version_policy="exclude"
    )
    assert ok is False


def test_extension_rule_not_applicable_to_strict_gt(rs):
    # Nginx / EXT rules are operational but excluded from strict-GT applicability.
    for rid in ("OJS-CFG-NGX-001", "OJS-CFG-EXT-COOKIE-001"):
        ok, _ = is_rule_applicable_to_version(rs.get(rid), "3.3.0-13")
        assert ok is False, rid


def test_missing_affected_versions_fails_for_ground_truth_rule():
    rule = Rule(
        id="OJS-CFG-SEC-001",  # ground-truth prefix
        name="synthetic",
        module="config",
        severity=Severity.HIGH,
        params={},  # deliberately missing affected_versions
    )
    ok, reason = is_rule_applicable_to_version(rule, "3.3.0-13")
    assert ok is False
    assert "missing affected_versions" in reason


def test_missing_affected_versions_universal_policy():
    rule = Rule(
        id="CVE-SRC-099",
        name="synthetic",
        module="source_code",
        severity=Severity.HIGH,
        params={},
    )
    ok, reason = is_rule_applicable_to_version(
        rule, "3.3.0-13", missing_affected_versions_policy="universal"
    )
    assert ok is True
    assert "universal" in reason


# --------------------------------------------------------------------------- #
# get_rule_evaluation_scope_for_version
# --------------------------------------------------------------------------- #
def test_get_rule_evaluation_scope_for_version(rs):
    meta = get_rule_evaluation_scope_for_version(rs.get("OJS-CFG-SEC-013"), "3.4.0-7")
    assert meta["ground_truth"] is True
    assert meta["evaluation_scope"] == "ground_truth"
    assert meta["applicable"] is False  # 3.5-only directive on a 3.4 scan
    assert "outside" in meta["applicability_reason"]

    meta35 = get_rule_evaluation_scope_for_version(rs.get("OJS-CFG-SEC-013"), "3.5.0-1")
    assert meta35["applicable"] is True
