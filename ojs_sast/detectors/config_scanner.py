"""Configuration scanner for ``config.inc.php`` and Nginx site configs.

Parses the OJS INI-style ``config.inc.php`` (``[section]`` headers, ``key = value``
pairs, ``;``/``#`` comments, a leading ``;<​?php exit; ?>`` guard) and evaluates
the OJS-CFG-* rules.  Nginx configs are scanned with targeted regexes.

Aligned to the OJS config SAST ground-truth dataset (30+ check IDs).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import Finding, Rule, Severity
from ..ruleset.loader import Ruleset

logger = logging.getLogger("ojs_sast.config")

_TRUE_WORDS = {"on", "1", "true", "yes", "enabled"}
_FALSE_WORDS = {"off", "0", "false", "no", "disabled", ""}


# --------------------------------------------------------------------------- #
# OJS config.inc.php parser
# --------------------------------------------------------------------------- #
def _strip_value(val: str) -> str:
    val = val.strip()
    if not val:
        return ""
    if val[0] in ('"', "'"):
        q = val[0]
        end = val.find(q, 1)
        return val[1:end] if end != -1 else val[1:]
    # Unquoted: drop trailing inline comment.
    for cmt in (";", "#"):
        idx = val.find(cmt)
        if idx != -1:
            val = val[:idx]
    return val.strip()


def parse_config(text: str) -> Dict[str, Dict[str, str]]:
    """Parse OJS config text into ``{section: {key: value}}`` (lowercased keys)."""
    sections: Dict[str, Dict[str, str]] = {"": {}}
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line[0] in (";", "#"):
            continue
        sec = re.match(r"\[([^\]]+)\]", line)
        if sec:
            current = sec.group(1).strip().lower()
            sections.setdefault(current, {})
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            sections.setdefault(current, {})[key.strip().lower()] = _strip_value(val)
    return sections


def get_value(sections: Dict[str, Dict[str, str]], section: str, key: str) -> Optional[str]:
    """Look up ``key`` in ``section``; fall back to any section (version drift)."""
    key = key.lower()
    sec = sections.get(section.lower(), {})
    if key in sec:
        return sec[key]
    for name, kv in sections.items():
        if key in kv:
            return kv[key]
    return None


def _as_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    v = value.strip().lower()
    if v in _TRUE_WORDS:
        return True
    if v in _FALSE_WORDS:
        return False
    return None


def _bool_equal(value: str, expected: str) -> bool:
    bv, be = _as_bool(value), _as_bool(expected)
    if bv is not None and be is not None:
        return bv == be
    return value.strip().lower() == expected.strip().lower()


def extract_upload_dirs(sections: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(files_dir, public_files_dir)`` from a parsed config."""
    files_dir = get_value(sections, "files", "files_dir")
    public_dir = get_value(sections, "files", "public_files_dir")
    return files_dir, public_dir


# --------------------------------------------------------------------------- #
# Config scanner
# --------------------------------------------------------------------------- #
class ConfigScanner:
    def __init__(self, ruleset: Ruleset, ojs_path: Optional[Path] = None,
                 ojs_version: Optional[str] = None, verbose: bool = False):
        self.ruleset = ruleset
        self.ojs_path = Path(ojs_path) if ojs_path else None
        self.ojs_version = ojs_version
        self.verbose = verbose

    def scan(self, config_path: Optional[Path],
             nginx_paths: Optional[List[Path]] = None) -> List[Finding]:
        findings: List[Finding] = []
        config_rules = [r for r in self.ruleset.by_module("config")]

        if config_path and Path(config_path).is_file():
            text = Path(config_path).read_text(encoding="utf-8", errors="replace")
            sections = parse_config(text)
            rel = str(config_path)
            for rule in config_rules:
                check = rule.params.get("check")
                if check and not check.startswith("nginx_"):
                    f = self._run_check(rule, check, text, sections, rel)
                    if f:
                        findings.extend(f)
        else:
            logger.warning("config.inc.php not found at %s; skipping config checks", config_path)

        # Nginx
        nginx_text, nginx_label = self._load_nginx(nginx_paths)
        if nginx_text is not None:
            for rule in config_rules:
                check = rule.params.get("check", "")
                if check.startswith("nginx_"):
                    findings.extend(self._run_nginx_check(rule, check, nginx_text, nginx_label))
        elif nginx_paths:
            logger.warning("No readable Nginx config found at provided path(s)")

        logger.info("Config scan complete: %d findings", len(findings))
        return findings

    # -- config.inc.php checks --------------------------------------------- #
    def _run_check(self, rule: Rule, check: str, text: str,
                   sections: Dict[str, Dict[str, str]], rel: str) -> List[Finding]:
        handler = getattr(self, f"_check_{check}", None)
        if handler is None:
            logger.debug("No handler for config check %s (rule %s)", check, rule.id)
            return []
        return handler(rule, text, sections, rel)

    def _finding(self, rule: Rule, file_path: str, detail: str,
                 severity: Optional[Severity] = None, **kw) -> Finding:
        return Finding(
            rule_id=rule.id,
            module="config",
            severity=severity or rule.severity,
            file_path=file_path,
            title=rule.name,
            detail=detail,
            remediation=rule.remediation,
            cwe=rule.cwe,
            owasp=rule.owasp,
            cvss_score=rule.cvss_score,
            cve_references=list(rule.cve_references),
            confidence="high",
            **kw,
        )

    # -- guard_line -------------------------------------------------------- #
    def _check_guard_line(self, rule, text, sections, rel) -> List[Finding]:
        tokens = [t.lower() for t in rule.params.get("guard_tokens", ["<?php", "exit"])]
        n = int(rule.params.get("scan_lines", 3))
        head = "\n".join(text.splitlines()[:n]).lower()
        if all(tok in head for tok in tokens):
            return []
        return [self._finding(rule, rel,
                              "The leading ';<?php exit; ?>' guard is missing from config.inc.php.")]

    # -- value_strength ---------------------------------------------------- #
    def _check_value_strength(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "security")
        key = rule.params.get("key")
        value = get_value(sections, section, key)
        defaults = {str(d).lower() for d in rule.params.get("default_values", [])}
        min_len = int(rule.params.get("min_length", 0))
        if value is None:
            return [self._finding(rule, rel, f"'{key}' is not set in [{section}].")]
        if value.lower() in defaults:
            reason = "empty" if value == "" else f"a known default ('{value}')"
            return [self._finding(rule, rel, f"'{key}' is set to {reason}.")]
        if min_len and len(value) < min_len:
            return [self._finding(rule, rel,
                                  f"'{key}' is only {len(value)} characters; at least "
                                  f"{min_len} are recommended.")]
        return []

    # -- allowed_hosts ----------------------------------------------------- #
    def _check_allowed_hosts(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key", "allowed_hosts")
        value = get_value(sections, section, key)
        if value is None or value.strip() == "":
            return [self._finding(rule, rel,
                                  "'allowed_hosts' is empty, so OJS trusts the inbound Host "
                                  "header (Host header injection).")]
        if "*" in value:
            return [self._finding(rule, rel,
                                  f"'allowed_hosts' uses a wildcard ('{value}'); trusts arbitrary "
                                  f"Host headers.")]
        return []

    # -- bool_directive ---------------------------------------------------- #
    def _check_bool_directive(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key")
        secure = rule.params.get("secure_value")
        insecure = rule.params.get("insecure_value")
        value = get_value(sections, section, key)

        if value is None:
            return self._absent(rule, key, rel, secure)

        if insecure is not None:
            if _bool_equal(value, insecure):
                return [self._finding(rule, rel, f"'{key}' is set to '{value}' (insecure).")]
            return []
        if secure is not None and not _bool_equal(value, secure):
            return [self._finding(rule, rel,
                                  f"'{key}' is '{value}'; should be '{secure}'.")]
        return []

    # -- enum_directive ---------------------------------------------------- #
    def _check_enum_directive(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key")
        secure_values = {str(v).lower() for v in rule.params.get("secure_values", [])}
        value = get_value(sections, section, key)
        if value is None:
            return self._absent(rule, key, rel,
                                rule.params.get("default_when_absent"), secure_values)
        if value.strip().lower() in secure_values:
            return []
        return [self._finding(rule, rel,
                              f"'{key}' is '{value}'; expected one of "
                              f"{sorted(rule.params.get('secure_values', []))}.")]

    # -- integer_threshold ------------------------------------------------- #
    def _check_integer_threshold(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key")
        operator = rule.params.get("operator", "<=")
        threshold = int(rule.params.get("threshold", 0))
        default = rule.params.get("default_when_absent")
        warn_sev = rule.params.get("warn_severity", "low")

        value = get_value(sections, section, key)
        if value is None:
            if default is not None:
                value = str(default)
            else:
                return [self._finding(rule, rel, f"'{key}' is not set in [{section}].",
                                      severity=Severity.from_str(warn_sev))]

        try:
            val = int(value.strip())
        except (ValueError, AttributeError):
            return [self._finding(rule, rel, f"'{key}' has non-numeric value '{value}'.")]

        passed = False
        if operator == "<=":
            passed = val <= threshold
        elif operator == "<":
            passed = val < threshold
        elif operator == ">":
            passed = val > threshold
        elif operator == ">=":
            passed = val >= threshold
        elif operator == "==":
            passed = val == threshold

        if passed:
            return []
        return [self._finding(rule, rel,
                              f"'{key}' is {val}; expected {operator} {threshold}.",
                              severity=Severity.from_str(warn_sev))]

    # -- base_url_scheme --------------------------------------------------- #
    def _check_base_url_scheme(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key", "base_url")
        value = get_value(sections, section, key)
        findings: List[Finding] = []

        if value is None:
            return [self._finding(rule, rel, f"'{key}' is not set.")]

        # Check placeholder values.
        placeholders = rule.params.get("placeholder_values", [])
        if value.strip().lower() in [p.lower() for p in placeholders]:
            findings.append(self._finding(rule, rel,
                                          f"'{key}' is still the default placeholder ('{value}')."))

        # Check scheme.
        required = rule.params.get("required_scheme", "https")
        if value.strip().lower().startswith("http://"):
            findings.append(self._finding(rule, rel,
                                          f"'{key}' uses HTTP instead of HTTPS."))

        return findings

    # -- allowed_html_tags ------------------------------------------------- #
    def _check_allowed_html_tags(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "security")
        key = rule.params.get("key", "allowed_html")
        value = get_value(sections, section, key)
        if value is None:
            return []  # Default is safe.

        dangerous = rule.params.get("dangerous_patterns", [])
        found = []
        for pat in dangerous:
            if re.search(pat, value, re.IGNORECASE):
                found.append(pat)

        if found:
            return [self._finding(rule, rel,
                                  f"'allowed_html' contains dangerous tag(s): {', '.join(found)}.")]
        return []

    # -- captcha_engine ---------------------------------------------------- #
    def _check_captcha_engine(self, rule, text, sections, rel) -> List[Finding]:
        captcha_sec = sections.get("captcha", {})
        recaptcha = captcha_sec.get("recaptcha", "off").strip().lower()
        altcha = captcha_sec.get("altcha", "off").strip().lower()

        if recaptcha in _TRUE_WORDS or altcha in _TRUE_WORDS:
            return []
        return [self._finding(rule, rel,
                              "Neither reCAPTCHA nor ALTCHA is enabled in [captcha]. "
                              "No bot protection on registration/login.")]

    # -- breached_password ------------------------------------------------- #
    def _check_breached_password(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "database")
        key = rule.params.get("key", "password")
        value = get_value(sections, section, key)
        if not value:
            return []
        breached = {str(p).lower() for p in rule.params.get("breached_passwords", [])}
        if value.lower() in breached:
            return [self._finding(rule, rel,
                                  "The database password matches a common/breached password.")]
        return []

    # -- password_equals_identity ------------------------------------------ #
    def _check_password_equals_identity(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "database")
        key = rule.params.get("key", "password")
        password = get_value(sections, section, key)
        if not password:
            return []
        for cmp_key in rule.params.get("compare_keys", ["username", "name"]):
            other = get_value(sections, section, cmp_key)
            if other and password == other:
                return [self._finding(rule, rel,
                                      f"The database password equals the database {cmp_key} "
                                      f"('{other}').")]
        return []

    # -- files_dir_webroot ------------------------------------------------- #
    def _check_files_dir_webroot(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "files")
        key = rule.params.get("key", "files_dir")
        value = get_value(sections, section, key)
        if not value:
            return []
        p = Path(value)
        if not p.is_absolute():
            return [self._finding(rule, rel,
                                  f"'files_dir' is a relative path ('{value}'), resolving inside "
                                  f"the OJS web root.")]
        if self.ojs_path:
            try:
                fd = p.resolve()
                root = self.ojs_path.resolve()
                if fd == root or root in fd.parents:
                    return [self._finding(rule, rel,
                                          f"'files_dir' ('{value}') is inside the OJS install/web "
                                          f"root ({root}).")]
            except OSError:  # pragma: no cover
                pass
        return []

    # -- absent directive helper ------------------------------------------- #
    def _absent(self, rule, key, rel, secure_value, secure_set=None) -> List[Finding]:
        """Handle an absent directive, honoring secure-by-default versions."""
        default = rule.params.get("default_when_absent")
        is_secure_default = False
        if default is not None:
            if secure_set is not None:
                is_secure_default = str(default).lower() in secure_set
            elif secure_value is not None:
                is_secure_default = _bool_equal(str(default), str(secure_value))
        if is_secure_default:
            absent_sev = rule.params.get("absent_severity")
            if not absent_sev:
                return []
            since = rule.params.get("default_since")
            note = f" (default '{default}' since OJS {since})" if since else f" (default '{default}')"
            return [self._finding(rule, rel,
                                  f"'{key}' is not set; relying on the secure default{note}.",
                                  severity=Severity.from_str(absent_sev))]
        return [self._finding(rule, rel,
                              f"'{key}' is not set; the default '{default}' is insecure.")]

    # -- Nginx --------------------------------------------------------------- #
    def _load_nginx(self, nginx_paths: Optional[List[Path]]) -> Tuple[Optional[str], str]:
        if not nginx_paths:
            return None, ""
        texts: List[str] = []
        labels: List[str] = []
        for p in nginx_paths:
            p = Path(p)
            files: List[Path] = []
            if p.is_dir():
                files = [f for f in sorted(p.rglob("*")) if f.is_file()]
            elif p.is_file():
                files = [p]
            for f in files:
                try:
                    texts.append(f.read_text(encoding="utf-8", errors="replace"))
                    labels.append(str(f))
                except OSError:  # pragma: no cover
                    continue
        if not texts:
            return None, ""
        return "\n".join(texts), labels[0] if len(labels) == 1 else f"{labels[0]} (+{len(labels) - 1} more)"

    def _run_nginx_check(self, rule: Rule, check: str, text: str, label: str) -> List[Finding]:
        handler = getattr(self, f"_check_{check}", None)
        if handler is None:
            return []
        return handler(rule, text, label)

    def _check_nginx_upload_php_block(self, rule, text, label) -> List[Finding]:
        patterns = [
            r"location[^{}]*(?:files|public)[^{}]*\{[^}]*(?:deny\s+all|return\s+40\d|internal)",
            r"location\s*[~^][^{}]*\.php[^{}]*\{[^}]*deny\s+all",
        ]
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                return []
        return [self._finding(rule, label,
                              "No Nginx rule denies access/execution under the uploads "
                              "(files/public) directory.")]

    def _check_nginx_security_headers(self, rule, text, label) -> List[Finding]:
        findings: List[Finding] = []
        low = text.lower()
        for header in rule.params.get("required_headers", []):
            if header.lower() not in low:
                findings.append(self._finding(
                    rule, label,
                    f"Security header '{header}' is not configured.",
                    severity=rule.severity,
                    dedup_discriminator=header,
                    extra={"header": header},
                ))
        return findings

    def _check_nginx_server_tokens(self, rule, text, label) -> List[Finding]:
        if re.search(r"server_tokens\s+off\s*;", text, re.IGNORECASE):
            return []
        return [self._finding(rule, label, "'server_tokens off;' is not set; Nginx leaks its version.")]

    def _check_nginx_autoindex(self, rule, text, label) -> List[Finding]:
        if re.search(r"autoindex\s+on\s*;", text, re.IGNORECASE):
            return [self._finding(rule, label, "'autoindex on;' enables directory listing.")]
        return []
