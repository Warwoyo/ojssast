import pytest
from ojs_sast.ruleset.loader import load_ruleset

# All 39 Ground Truth OJS Configuration Checks
EXPECTED_CONFIG_GT = {
    # general
    "OJS-CFG-GEN-001": ("general", "installed"),
    "OJS-CFG-GEN-002": ("general", "base_url"),
    "OJS-CFG-GEN-003": ("general", "allowed_hosts"),
    "OJS-CFG-GEN-004": ("general", "trust_x_forwarded_for"),
    "OJS-CFG-GEN-005": ("general", "allow_url_fopen"),
    "OJS-CFG-GEN-006": ("general", "session_lifetime"),
    "OJS-CFG-GEN-007": ("general", "session_samesite"),
    "OJS-CFG-GEN-008": ("general", "sandbox"),
    "OJS-CFG-GEN-009": ("general", "show_upgrade_warning"),
    "OJS-CFG-GEN-010": ("general", "enable_beacon"),
    "OJS-CFG-GEN-011": ("general", "user_validation_period"),
    # security
    "OJS-CFG-SEC-001": ("security", "force_ssl"),
    "OJS-CFG-SEC-002": ("security", "force_login_ssl"),
    "OJS-CFG-SEC-003": ("security", "session_check_ip"),
    "OJS-CFG-SEC-004": ("security", "encryption"),
    "OJS-CFG-SEC-005": ("security", "session_expire_on_close"),
    "OJS-CFG-SEC-006": ("security", "salt"),
    "OJS-CFG-SEC-007": ("security", "api_key_secret"),
    "OJS-CFG-SEC-008": ("security", "reset_seconds"),
    "OJS-CFG-SEC-009": ("security", "allow_plugin_install"),
    "OJS-CFG-SEC-010": ("security", "password_timeout"),
    "OJS-CFG-SEC-011": ("security", "cipher"),
    "OJS-CFG-SEC-012": ("security", "cookie_encryption"),
    "OJS-CFG-SEC-013": ("general", "app_key"),
    "OJS-CFG-SEC-014": ("security", "allowed_html"),
    # database
    "OJS-CFG-DB-001": ("database", "username/password/name"),  # composite check: default_db_credentials
    "OJS-CFG-DB-002": ("database", "debug"),
    "OJS-CFG-DB-003": ("database", "secure"),  # composite check: db_secure_remote
    # files
    "OJS-CFG-FILE-001": ("files", "files_dir"),
    "OJS-CFG-FILE-002": ("files", "umask"),
    "OJS-CFG-FILE-003": ("files", "public_user_dir_size"),
    "OJS-CFG-FILE-004": ("files", "guard_line"),  # composite check: guard_line
    # email
    "OJS-CFG-EMAIL-001": ("email", "smtp_suppress_cert_check"),
    "OJS-CFG-EMAIL-002": ("email", "require_validation"),
    # captcha
    "OJS-CFG-CAP-001": ("captcha", "captcha_engine"),  # composite check: captcha_engine
    # debug
    "OJS-CFG-DBG-001": ("debug", "show_stacktrace"),
    "OJS-CFG-DBG-002": ("debug", "display_errors"),
    "OJS-CFG-DBG-003": ("debug", "deprecation_warnings"),
    "OJS-CFG-DBG-004": ("debug", "log_web_service_info"),
}


def test_ruleset_ground_truth_alignment(ruleset):
    config_rules = {r.id: r for r in ruleset.by_module("config")}

    # Assert that all 39 Ground Truth rules are present and correct
    for rid, (expected_sec, expected_key) in EXPECTED_CONFIG_GT.items():
        assert rid in config_rules, f"Rule {rid} is missing from the ruleset"
        rule = config_rules[rid]

        # Check section
        if rid == "OJS-CFG-FILE-004":
            # exit guard line check runs on the file header, so section parameter is absent/unused
            assert rule.params.get("section") is None
        elif rid == "OJS-CFG-CAP-001":
            # captcha checks the whole captcha section (using composite altcha/recaptcha)
            assert rule.params.get("section") == "captcha"
        else:
            actual_sec = rule.params.get("section")
            assert actual_sec == expected_sec, (
                f"Rule {rid} expected section '{expected_sec}', got '{actual_sec}'"
            )

        # Check key mapping
        if rid == "OJS-CFG-DB-001":
            assert rule.params.get("check") == "default_db_credentials"
        elif rid == "OJS-CFG-DB-003":
            assert rule.params.get("check") == "db_secure_remote"
        elif rid == "OJS-CFG-FILE-004":
            assert rule.params.get("check") == "guard_line"
        elif rid == "OJS-CFG-CAP-001":
            assert rule.params.get("check") == "captcha_engine"
        else:
            actual_key = rule.params.get("key")
            assert actual_key == expected_key, (
                f"Rule {rid} expected key '{expected_key}', got '{actual_key}'"
            )

    # Check extension rules (those not in the 39 GT rules list)
    for rule in config_rules.values():
        if rule.id not in EXPECTED_CONFIG_GT:
            # Allowlist OJS-CFG-NGX-* and OJS-CFG-EXT-* as non-GT extensions
            assert rule.id.startswith("OJS-CFG-NGX-") or rule.id.startswith("OJS-CFG-EXT-"), (
                f"Rule {rule.id} is not in the ground truth set and does not follow the extension ID prefix"
            )
            assert rule.params.get("ground_truth") is False, (
                f"Rule {rule.id} is an extension rule but is not marked as extension (ground_truth: false)"
            )
        else:
            # GT rules must not be marked as extension
            assert rule.params.get("ground_truth") is not False, (
                f"Ground truth rule {rule.id} must not be marked as extension"
            )
