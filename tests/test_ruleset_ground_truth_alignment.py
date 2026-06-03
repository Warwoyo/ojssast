import pytest
from ojs_sast.ruleset.loader import load_ruleset

EXPECTED_CONFIG_GT = {
    "OJS-CFG-GEN-009": ("general", "show_upgrade_warning"),
    "OJS-CFG-GEN-010": ("general", "enable_beacon"),
    "OJS-CFG-GEN-011": ("general", "user_validation_period"),
    "OJS-CFG-DB-001": ("database", "username/password/name"),  # composite username/password/name check
    "OJS-CFG-DB-002": ("database", "debug"),
    "OJS-CFG-DB-003": ("database", "secure"),  # composite host/secure/unix_socket check
    "OJS-CFG-FILE-003": ("files", "public_user_dir_size"),
}


def test_ruleset_ground_truth_alignment(ruleset):
    config_rules = {r.id: r for r in ruleset.by_module("config")}

    for rid, (expected_sec, expected_key) in EXPECTED_CONFIG_GT.items():
        assert rid in config_rules, f"Rule {rid} is missing from the ruleset"
        rule = config_rules[rid]

        # Check section
        actual_sec = rule.params.get("section")
        assert actual_sec == expected_sec, (
            f"Rule {rid} expected section '{expected_sec}', got '{actual_sec}'"
        )

        # Check key mapping
        if rid == "OJS-CFG-DB-001":
            # For OJS-CFG-DB-001 composite check
            assert rule.params.get("check") == "default_db_credentials"
        elif rid == "OJS-CFG-DB-003":
            # For OJS-CFG-DB-003 composite check
            assert rule.params.get("check") == "db_secure_remote"
        else:
            actual_key = rule.params.get("key")
            assert actual_key == expected_key, (
                f"Rule {rid} expected key '{expected_key}', got '{actual_key}'"
            )

    # Check that ground truth IDs are not used for different semantics
    for rule in config_rules.values():
        if rule.id in EXPECTED_CONFIG_GT:
            expected_sec, expected_key = EXPECTED_CONFIG_GT[rule.id]
            assert rule.params.get("section") == expected_sec
        else:
            # Allowlist OJS-CFG-NGX-* as non-GT extension, and check other extension rules
            assert rule.params.get("ground_truth") is False, (
                f"Rule {rule.id} is an extension rule but is not marked as extension (ground_truth: false)"
            )
