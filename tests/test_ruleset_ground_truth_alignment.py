# All 39 Ground Truth OJS Configuration Checks
CONFIG_GT_IDS = {
    *(f"OJS-CFG-GEN-{i:03d}" for i in range(1, 12)),
    *(f"OJS-CFG-SEC-{i:03d}" for i in range(1, 15)),
    *(f"OJS-CFG-DB-{i:03d}" for i in range(1, 4)),
    *(f"OJS-CFG-FILE-{i:03d}" for i in range(1, 5)),
    "OJS-CFG-EMAIL-001",
    "OJS-CFG-EMAIL-002",
    "OJS-CFG-CAP-001",
    *(f"OJS-CFG-DBG-{i:03d}" for i in range(1, 5)),
}

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

EXTENSION_CONFIG_PREFIXES = ("OJS-CFG-NGX-", "OJS-CFG-EXT-")
GENERIC_SOURCE_NON_GT_IDS = {"RULE-SRC-010", "RULE-SRC-011", "RULE-SRC-012"}
CVE_GT_IDS = {f"CVE-SRC-{i:03d}" for i in range(1, 13)}


def test_all_config_ground_truth_ids_exist(ruleset):
    config_rules = {rule.id: rule for rule in ruleset.by_module("config")}

    assert len(CONFIG_GT_IDS) == 39
    assert CONFIG_GT_IDS == set(EXPECTED_CONFIG_GT)
    missing_ids = sorted(CONFIG_GT_IDS - set(config_rules))
    assert not missing_ids, f"Missing config ground-truth rules: {missing_ids}"


def test_ruleset_ground_truth_alignment(ruleset):
    config_rules = {r.id: r for r in ruleset.by_module("config")}

    # Assert that all 39 Ground Truth rules are present and section/key aligned.
    for rid, (expected_sec, expected_key) in EXPECTED_CONFIG_GT.items():
        assert rid in config_rules, f"Rule {rid} is missing from the ruleset"
        rule = config_rules[rid]

        # Check section mapping.
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

        # Check key/check mapping.
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


def test_config_ground_truth_rules_not_marked_extension(ruleset):
    for rid in CONFIG_GT_IDS:
        rule = ruleset.get(rid)
        assert rule is not None, f"Rule {rid} is missing from the ruleset"
        assert rule.params.get("ground_truth") is not False, (
            f"Ground truth rule {rid} must not be marked as an extension/non-ground-truth rule"
        )


def test_extension_rules_marked_non_ground_truth(ruleset):
    config_rules = {rule.id: rule for rule in ruleset.by_module("config")}
    extension_rules = {
        rid: rule
        for rid, rule in config_rules.items()
        if rid.startswith(EXTENSION_CONFIG_PREFIXES)
    }
    unexpected_non_gt_ids = sorted(
        rid
        for rid in set(config_rules) - CONFIG_GT_IDS
        if not rid.startswith(EXTENSION_CONFIG_PREFIXES)
    )

    assert not unexpected_non_gt_ids, (
        "Config rules outside the 39 ground-truth IDs must use an extension prefix: "
        f"{unexpected_non_gt_ids}"
    )
    assert extension_rules, "Expected at least one OJS-CFG-NGX-* or OJS-CFG-EXT-* extension rule"
    for rid, rule in extension_rules.items():
        assert rid not in CONFIG_GT_IDS
        assert rule.params.get("ground_truth") is False, (
            f"Extension config rule {rid} must be marked ground_truth: false"
        )


def test_generic_source_rules_marked_non_ground_truth(ruleset):
    for rid in GENERIC_SOURCE_NON_GT_IDS:
        rule = ruleset.get(rid)
        assert rule is not None, f"Rule {rid} is missing from the ruleset"
        assert rule.params.get("ground_truth") is False, (
            f"Generic source rule {rid} must be marked ground_truth: false"
        )


def test_cve_rules_are_ground_truth(ruleset):
    for rid in CVE_GT_IDS:
        rule = ruleset.get(rid)
        assert rule is not None, f"Rule {rid} is missing from the ruleset"
        assert rule.params.get("ground_truth") is not False, (
            f"CVE rule {rid} must remain in the ground-truth ruleset"
        )


def test_ground_truth_config_rules_declare_affected_versions(ruleset):
    """Every ground-truth config rule must declare explicit affected_versions.

    affected_versions controls version applicability (not rule loading); a missing
    value would make version-aware evaluation impossible, so this must fail loudly.
    """
    missing = []
    for rid in CONFIG_GT_IDS:
        rule = ruleset.get(rid)
        assert rule is not None, f"Rule {rid} is missing from the ruleset"
        if not rule.params.get("affected_versions"):
            missing.append(rid)
    assert not missing, f"Ground-truth config rules missing affected_versions: {missing}"


def test_ground_truth_cve_rules_declare_affected_versions(ruleset):
    missing = [
        rid for rid in CVE_GT_IDS
        if not (ruleset.get(rid) and ruleset.get(rid).params.get("affected_versions"))
    ]
    assert not missing, f"CVE ground-truth rules missing affected_versions: {missing}"


def test_extension_config_rules_excluded_from_strict_gt_applicability(ruleset):
    """Nginx/EXT rules stay non-ground-truth and are not strict-GT applicable."""
    from ojs_sast.helpers.rule_applicability import is_rule_applicable_to_version

    for rid, rule in ((r.id, r) for r in ruleset.by_module("config")):
        if rid.startswith(EXTENSION_CONFIG_PREFIXES):
            assert rule.params.get("ground_truth") is False
            applicable, _ = is_rule_applicable_to_version(rule, "3.5.0-1")
            assert applicable is False, (
                f"Extension rule {rid} must not be strict-GT applicable"
            )
