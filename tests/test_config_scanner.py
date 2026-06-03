"""Tests for the configuration scanner (config.inc.php + Nginx)."""

from ojs_sast.detectors.config_scanner import (ConfigScanner, extract_upload_dirs,
                                               get_value, parse_config)

from .conftest import FIXTURES


def _ids(findings):
    return {f.rule_id for f in findings}


def _by_id(findings):
    return {f.rule_id: f for f in findings}


# ----------------------------- parser ------------------------------------- #
def test_parser_sections_and_quotes():
    text = '[security]\nsalt = "a;b"\nforce_ssl = Off ; inline comment\n'
    sections = parse_config(text)
    assert sections["security"]["salt"] == "a;b"
    assert sections["security"]["force_ssl"] == "Off"


def test_get_value_fallback_across_sections():
    sections = parse_config("[general]\nsession_samesite = Lax\n")
    assert get_value(sections, "security", "session_samesite") == "Lax"


def test_extract_upload_dirs():
    sections = parse_config("[files]\nfiles_dir = /var/files\npublic_files_dir = public\n")
    assert extract_upload_dirs(sections) == ("/var/files", "public")


# ----------------------------- insecure config ---------------------------- #
def test_insecure_config_findings(ruleset, tmp_path):
    cfg = FIXTURES / "config" / "insecure_config.inc.php"
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    ids = _ids(sc.scan(cfg))
    expected = {
        "OJS-CFG-FILE-004",        # missing guard line
        "OJS-CFG-SEC-001",         # force_ssl Off (in config_rules force_ssl is OJS-CFG-SEC-001)
        "OJS-CFG-SEC-006",         # salt changeme (OJS-CFG-SEC-006)
        "OJS-CFG-SEC-007",         # empty api_key_secret (OJS-CFG-SEC-007)
        "OJS-CFG-GEN-003",         # wildcard allowed_hosts (OJS-CFG-GEN-003)
        "OJS-CFG-EXT-COOKIE-001",  # httponly Off (OJS-CFG-EXT-COOKIE-001)
        "OJS-CFG-GEN-007",         # samesite None (OJS-CFG-GEN-007)
        "OJS-CFG-DBG-001",         # show_stacktrace On (OJS-CFG-DBG-001)
        "OJS-CFG-DB-001",          # breached password "password" (OJS-CFG-DB-001)
        "OJS-CFG-FILE-001",        # relative files_dir (OJS-CFG-FILE-001)
        "OJS-CFG-EXT-PATH-INFO",   # disable_path_info Off (OJS-CFG-EXT-PATH-INFO)
    }
    assert expected <= ids


def test_hardened_config_clean(ruleset):
    cfg = FIXTURES / "config" / "hardened_config.inc.php"
    sc = ConfigScanner(ruleset, ojs_path="/var/www/ojs")
    assert sc.scan(cfg) == []


def test_guard_line_present_not_flagged(ruleset, tmp_path):
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[security]\nsalt = " + "z" * 40 + "\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    assert "OJS-CFG-FILE-004" not in _ids(sc.scan(cfg))


def test_salt_too_short(ruleset, tmp_path):
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[security]\nsalt = short\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings = _by_id(sc.scan(cfg))
    assert "OJS-CFG-SEC-006" in findings
    assert findings["OJS-CFG-SEC-006"].severity.value == "CRITICAL"


def test_password_equals_username(ruleset, tmp_path):
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[database]\nusername = ojsadmin\npassword = ojsadmin\nname = db\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    assert "OJS-CFG-DB-001" in _ids(sc.scan(cfg))


def test_files_dir_absolute_outside_not_flagged(ruleset, tmp_path):
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[files]\nfiles_dir = /var/lib/ojs/files\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path / "webroot")
    assert "OJS-CFG-FILE-001" not in _ids(sc.scan(cfg))


def test_absent_httponly_is_info(ruleset, tmp_path):
    # httponly absent -> secure default On in 3.3.0+ -> INFO, not MEDIUM.
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[general]\nbase_url = x\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    by = _by_id(sc.scan(cfg))
    assert "OJS-CFG-EXT-COOKIE-001" in by
    assert by["OJS-CFG-EXT-COOKIE-001"].severity.value == "INFO"


# ----------------------------- nginx -------------------------------------- #
def test_nginx_insecure(ruleset, tmp_path):
    nginx = FIXTURES / "config" / "nginx_insecure.conf"
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[general]\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    ids = _ids(sc.scan(cfg, [nginx]))
    assert {"OJS-CFG-NGX-001", "OJS-CFG-NGX-002", "OJS-CFG-NGX-003", "OJS-CFG-NGX-004"} <= ids


def test_nginx_security_headers_separate_findings(ruleset, tmp_path):
    nginx = FIXTURES / "config" / "nginx_insecure.conf"
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    ngx2 = [f for f in sc.scan(cfg, [nginx]) if f.rule_id == "OJS-CFG-NGX-002"]
    assert len(ngx2) == 4  # one per missing header (not collapsed)


def test_nginx_hardened_clean(ruleset, tmp_path):
    nginx = FIXTURES / "config" / "nginx_hardened.conf"
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    ngx = [f for f in sc.scan(cfg, [nginx]) if f.rule_id.startswith("OJS-CFG-NGX")]
    assert ngx == []


# ----------------------------- snippet checks ----------------------------- #
def test_allowed_hosts_wildcard_has_snippet(ruleset, tmp_path):
    """allowed_hosts = * produces a code_snippet with ≥5 lines and >>> marker."""
    cfg = FIXTURES / "config" / "insecure_config.inc.php"
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings = [f for f in sc.scan(cfg) if f.rule_id == "OJS-CFG-GEN-003"]
    assert len(findings) >= 1
    snippet = findings[0].code_snippet
    assert snippet is not None
    lines = snippet.strip().splitlines()
    assert len(lines) >= 5
    assert any(">>>" in l and "allowed_hosts" in l for l in lines)


def test_absent_directive_has_snippet(ruleset, tmp_path):
    """An absent directive produces a snippet with the missing-evidence marker."""
    cfg = tmp_path / "c.inc.php"
    # No allowed_hosts key at all.
    cfg.write_text(";<?php exit; ?>\n[general]\nbase_url = https://x\n"
                   "installed = On\nfoo = bar\nbaz = qux\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    by = _by_id(sc.scan(cfg))
    # allowed_hosts absent should produce a snippet with missing-directive marker.
    if "OJS-CFG-GEN-003" in by:
        snippet = by["OJS-CFG-GEN-003"].code_snippet
        assert snippet is not None
        assert ">>> SAST: missing expected directive" in snippet


def test_nginx_autoindex_snippet(ruleset, tmp_path):
    """autoindex on; produces ≥5 lines snippet with marker on that line."""
    nginx = FIXTURES / "config" / "nginx_insecure.conf"
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[general]\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings = [f for f in sc.scan(cfg, [nginx]) if f.rule_id == "OJS-CFG-NGX-004"]
    assert len(findings) >= 1
    snippet = findings[0].code_snippet
    assert snippet is not None
    lines = snippet.strip().splitlines()
    assert len(lines) >= 5
    assert any(">>>" in l and "autoindex" in l for l in lines)


def test_nginx_missing_upload_block_snippet(ruleset, tmp_path):
    """Missing upload PHP deny block produces snippet with missing evidence."""
    nginx = FIXTURES / "config" / "nginx_insecure.conf"
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings = [f for f in sc.scan(cfg, [nginx]) if f.rule_id == "OJS-CFG-NGX-001"]
    assert len(findings) >= 1
    snippet = findings[0].code_snippet
    assert snippet is not None
    assert ">>> SAST: missing expected directive" in snippet


def test_config_findings_all_have_snippets(ruleset, tmp_path):
    """All config findings should have code_snippet populated."""
    cfg = FIXTURES / "config" / "insecure_config.inc.php"
    nginx = FIXTURES / "config" / "nginx_insecure.conf"
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings = sc.scan(cfg, [nginx])
    for f in findings:
        assert f.code_snippet is not None and len(f.code_snippet) > 0, \
            f"Finding {f.rule_id} missing code_snippet"


# ----------------------------- regression alignment tests ---------------- #
def test_regression_user_validation_period(ruleset, tmp_path):
    """Test OJS-CFG-GEN-011 logic."""
    cfg1 = tmp_path / "c1.inc.php"
    cfg1.write_text(";<?php exit; ?>\n[general]\nuser_validation_period = 0\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings1 = _ids(sc.scan(cfg1))
    assert "OJS-CFG-GEN-011" in findings1

    cfg2 = tmp_path / "c2.inc.php"
    cfg2.write_text(";<?php exit; ?>\n[general]\nuser_validation_period = 14\n")
    findings2 = _ids(sc.scan(cfg2))
    assert "OJS-CFG-GEN-011" not in findings2


def test_regression_default_db_credentials(ruleset, tmp_path):
    """Test OJS-CFG-DB-001 logic."""
    cfg1 = tmp_path / "c1.inc.php"
    cfg1.write_text(";<?php exit; ?>\n[database]\nusername = ojs\npassword = ojs\nname = ojs\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings1 = _ids(sc.scan(cfg1))
    assert "OJS-CFG-DB-001" in findings1

    cfg2 = tmp_path / "c2.inc.php"
    cfg2.write_text(";<?php exit; ?>\n[database]\nusername = ojs_user\npassword = strong_and_long_pwd_123!\nname = ojs_db\n")
    findings2 = _ids(sc.scan(cfg2))
    assert "OJS-CFG-DB-001" not in findings2


def test_regression_db_debug(ruleset, tmp_path):
    """Test OJS-CFG-DB-002 logic."""
    cfg1 = tmp_path / "c1.inc.php"
    cfg1.write_text(";<?php exit; ?>\n[database]\ndebug = On\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings1 = _ids(sc.scan(cfg1))
    assert "OJS-CFG-DB-002" in findings1

    # missing debug -> pass
    cfg2 = tmp_path / "c2.inc.php"
    cfg2.write_text(";<?php exit; ?>\n[database]\nhost = localhost\n")
    findings2 = _ids(sc.scan(cfg2))
    assert "OJS-CFG-DB-002" not in findings2


def test_regression_db_secure_remote(ruleset, tmp_path):
    """Test OJS-CFG-DB-003 logic."""
    # host remote, secure Off -> fail
    cfg1 = tmp_path / "c1.inc.php"
    cfg1.write_text(";<?php exit; ?>\n[database]\nhost = db.example.org\nsecure = Off\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings1 = _ids(sc.scan(cfg1))
    assert "OJS-CFG-DB-003" in findings1

    # host local, secure Off -> pass
    cfg2 = tmp_path / "c2.inc.php"
    cfg2.write_text(";<?php exit; ?>\n[database]\nhost = localhost\nsecure = Off\n")
    findings2 = _ids(sc.scan(cfg2))
    assert "OJS-CFG-DB-003" not in findings2

    # unix socket set -> pass
    cfg3 = tmp_path / "c3.inc.php"
    cfg3.write_text(";<?php exit; ?>\n[database]\nhost = db.example.org\nunix_socket = /var/run/mysql.sock\n")
    findings3 = _ids(sc.scan(cfg3))
    assert "OJS-CFG-DB-003" not in findings3

    # host remote, secure On -> pass
    cfg4 = tmp_path / "c4.inc.php"
    cfg4.write_text(";<?php exit; ?>\n[database]\nhost = db.example.org\nsecure = On\n")
    findings4 = _ids(sc.scan(cfg4))
    assert "OJS-CFG-DB-003" not in findings4


def test_regression_public_user_dir_size(ruleset, tmp_path):
    """Test OJS-CFG-FILE-003 logic."""
    cfg1 = tmp_path / "c1.inc.php"
    cfg1.write_text(";<?php exit; ?>\n[files]\npublic_user_dir_size = 6000\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings1 = sc.scan(cfg1)
    by1 = _by_id(findings1)
    assert "OJS-CFG-FILE-003" in by1
    assert by1["OJS-CFG-FILE-003"].severity.value == "LOW"

    cfg2 = tmp_path / "c2.inc.php"
    cfg2.write_text(";<?php exit; ?>\n[files]\npublic_user_dir_size = 5000\n")
    findings2 = _ids(sc.scan(cfg2))
    assert "OJS-CFG-FILE-003" not in findings2


def test_regression_informational_rules(ruleset, tmp_path):
    """Test show_upgrade_warning and enable_beacon do not generate security findings."""
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[general]\nshow_upgrade_warning = On\nenable_beacon = Off\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    findings = sc.scan(cfg)
    ids = _ids(findings)
    # The findings should not be emitted (since reporting is false)
    assert "OJS-CFG-GEN-009" not in ids
    assert "OJS-CFG-GEN-010" not in ids
