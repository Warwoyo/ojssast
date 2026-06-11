"""Tests for ConfigScanner.scan_payload / scan_texts (remote config mode)."""

from __future__ import annotations

from pathlib import Path

from ojs_sast.detectors.config_scanner import ConfigScanner

FIXTURES = Path(__file__).parent / "fixtures"
OJS_VERSION = "3.3.0-13"


def test_scan_payload_matches_scan_for_config(ruleset):
    cfg = FIXTURES / "config" / "insecure_config.inc.php"
    text = cfg.read_text(encoding="utf-8")

    via_path = {f.rule_id for f in ConfigScanner(ruleset, ojs_version=OJS_VERSION).scan(cfg)}
    via_payload = {f.rule_id for f in ConfigScanner(ruleset, ojs_version=OJS_VERSION)
                   .scan_payload({"config.inc.php": text})}

    assert via_path == via_payload
    assert via_path, "expected the insecure config to produce findings"


def test_scan_payload_file_path_label(ruleset):
    text = (FIXTURES / "config" / "insecure_config.inc.php").read_text(encoding="utf-8")
    findings = ConfigScanner(ruleset, ojs_version=OJS_VERSION).scan_payload(
        {"config.inc.php": text})
    config_findings = [f for f in findings if f.module == "config"]
    assert config_findings
    assert all(f.file_path == "config.inc.php" for f in config_findings)


def test_scan_payload_nginx_matches_scan(ruleset):
    nginx = FIXTURES / "config" / "nginx_insecure.conf"
    ntext = nginx.read_text(encoding="utf-8")

    via_path = {f.rule_id for f in ConfigScanner(ruleset).scan(None, [nginx])}
    via_payload = {f.rule_id for f in ConfigScanner(ruleset)
                   .scan_payload({"nginx:/etc/nginx/sites-enabled/ojs": ntext})}

    assert via_path == via_payload
    assert via_path, "expected the insecure nginx config to produce findings"


def test_scan_payload_routes_config_and_nginx_together(ruleset):
    cfg_text = (FIXTURES / "config" / "insecure_config.inc.php").read_text(encoding="utf-8")
    nginx_text = (FIXTURES / "config" / "nginx_insecure.conf").read_text(encoding="utf-8")
    findings = ConfigScanner(ruleset, ojs_version=OJS_VERSION).scan_payload({
        "config.inc.php": cfg_text,
        "nginx:/etc/nginx/sites-enabled/ojs": nginx_text,
    })
    file_paths = {f.file_path for f in findings}
    assert "config.inc.php" in file_paths
    assert any(p.startswith("nginx:") for p in file_paths)


def test_scan_texts_handles_missing_config(ruleset):
    """No config text + only nginx text still runs the nginx checks."""
    nginx_text = (FIXTURES / "config" / "nginx_insecure.conf").read_text(encoding="utf-8")
    findings = ConfigScanner(ruleset).scan_texts(None, [(nginx_text, "nginx:x")])
    assert findings  # nginx checks fired without any config.inc.php


def test_config_payload_ignores_apache_for_nginx_checks(ruleset):
    """Apache config entries (keyed ``apache:...``) must not be routed to nginx checks."""
    apache_conf = """\
<VirtualHost *:80>
    ServerName ojs.example.com
    DocumentRoot /var/www/ojs
</VirtualHost>
"""
    # Only apache key, no nginx key.
    findings = ConfigScanner(ruleset).scan_payload({
        "apache:/etc/apache2/sites-enabled/ojs.conf": apache_conf,
    })
    nginx_findings = [f for f in findings
                      if str(f.rule_id).startswith("OJS-CFG-NGX")]
    assert not nginx_findings, (
        f"Apache config wrongly triggered nginx findings: "
        f"{[f.rule_id for f in nginx_findings]}")

