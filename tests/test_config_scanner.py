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
        "OJS-CFG-FILE-004",   # missing guard line
        "OJS-CFG-SEC-001",    # salt changeme
        "OJS-CFG-SEC-002",    # empty api_key_secret
        "OJS-CFG-SEC-003",    # wildcard allowed_hosts
        "OJS-CFG-SEC-004",    # force_ssl Off
        "OJS-CFG-SEC-005",    # httponly Off
        "OJS-CFG-SEC-006",    # samesite None
        "OJS-CFG-SEC-007",    # show_stacktrace On
        "OJS-CFG-DB-001",     # breached password "password"
        "OJS-CFG-FILES-001",  # relative files_dir
        "OJS-CFG-FILES-002",  # disable_path_info Off
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
    assert "OJS-CFG-SEC-001" in findings
    assert findings["OJS-CFG-SEC-001"].severity.value == "CRITICAL"


def test_password_equals_username(ruleset, tmp_path):
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[database]\nusername = ojsadmin\npassword = ojsadmin\nname = db\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    assert "OJS-CFG-DB-002" in _ids(sc.scan(cfg))


def test_files_dir_absolute_outside_not_flagged(ruleset, tmp_path):
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[files]\nfiles_dir = /var/lib/ojs/files\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path / "webroot")
    assert "OJS-CFG-FILES-001" not in _ids(sc.scan(cfg))


def test_absent_httponly_is_info(ruleset, tmp_path):
    # httponly absent -> secure default On in 3.3.0+ -> INFO, not MEDIUM.
    cfg = tmp_path / "c.inc.php"
    cfg.write_text(";<?php exit; ?>\n[general]\nbase_url = x\n")
    sc = ConfigScanner(ruleset, ojs_path=tmp_path)
    by = _by_id(sc.scan(cfg))
    assert "OJS-CFG-SEC-005" in by
    assert by["OJS-CFG-SEC-005"].severity.value == "INFO"


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
