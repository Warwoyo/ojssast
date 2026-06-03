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

from ..helpers.snippet_utils import build_code_snippet, build_missing_evidence_snippet
from ..models import Finding, Rule, Severity, resolve_rule_metadata
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


def find_config_key_line(text: str, section: str, key: str) -> Optional[int]:
    """Find the line number where ``key = ...`` appears under ``[section]``."""
    in_section = False
    sec_lower = section.lower()
    key_lower = key.lower()
    for i, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        sec_m = re.match(r"\[([^\]]+)\]", line)
        if sec_m:
            in_section = sec_m.group(1).strip().lower() == sec_lower
            continue
        if in_section and "=" in line:
            k, _, _ = line.partition("=")
            if k.strip().lower() == key_lower:
                return i
    return None


def find_section_line(text: str, section: str) -> Optional[int]:
    """Find the line number of the ``[section]`` header."""
    sec_lower = section.lower()
    for i, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        sec_m = re.match(r"\[([^\]]+)\]", line)
        if sec_m and sec_m.group(1).strip().lower() == sec_lower:
            return i
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
                if rule.params.get("reporting") is False:
                    continue
                check = rule.params.get("check")
                if check and not check.startswith("nginx_"):
                    f = self._run_check(rule, check, text, sections, rel)
                    if f:
                        findings.extend(f)
        else:
            logger.warning("config.inc.php not found at %s; skipping config checks", config_path)

        # Nginx — process each file individually for accurate line numbers.
        nginx_files = self._load_nginx(nginx_paths)
        if nginx_files:
            for rule in config_rules:
                if rule.params.get("reporting") is False:
                    continue
                check = rule.params.get("check", "")
                if check.startswith("nginx_"):
                    for nx_text, nx_label in nginx_files:
                        findings.extend(self._run_nginx_check(rule, check, nx_text, nx_label))
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
        extra = dict(kw.pop("extra", {}))
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
            **resolve_rule_metadata(rule.id, rule.params),
            confidence="high",
            extra=extra,
            **kw,
        )

    # -- snippet builders for config ---------------------------------------- #
    @staticmethod
    def _snippet_for_key(text: str, section: str, key: str) -> str:
        """Build a code snippet highlighting the line where *key* is set."""
        line = find_config_key_line(text, section, key)
        if line is not None:
            return build_code_snippet(text, line)
        # Key not found in expected section — fall back to section header.
        return ConfigScanner._snippet_for_section(text, section)

    @staticmethod
    def _snippet_for_section(text: str, section: str) -> str:
        """Build a snippet anchored on a section header."""
        line = find_section_line(text, section)
        if line is not None:
            return build_code_snippet(text, line)
        # Section not found — show file head.
        return build_code_snippet(text, 1)

    @staticmethod
    def _snippet_missing_key(text: str, section: str, key: str) -> str:
        """Build a missing-evidence snippet for an absent key."""
        anchor = find_section_line(text, section)
        return build_missing_evidence_snippet(text, anchor, key)

    # -- guard_line -------------------------------------------------------- #
    def _check_guard_line(self, rule, text, sections, rel) -> List[Finding]:
        tokens = [t.lower() for t in rule.params.get("guard_tokens", ["<?php", "exit"])]
        n = int(rule.params.get("scan_lines", 3))
        head = "\n".join(text.splitlines()[:n]).lower()
        if all(tok in head for tok in tokens):
            return []
        snippet = build_missing_evidence_snippet(text, 1, "guard line ;<?php exit; ?>")
        return [self._finding(rule, rel,
                              "The leading ';<?php exit; ?>' guard is missing from config.inc.php.",
                              code_snippet=snippet)]

    # -- value_strength ---------------------------------------------------- #
    def _check_value_strength(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "security")
        key = rule.params.get("key")
        value = get_value(sections, section, key)
        defaults = {str(d).lower() for d in rule.params.get("default_values", [])}
        min_len = int(rule.params.get("min_length", 0))
        if value is None:
            snippet = self._snippet_missing_key(text, section, key)
            return [self._finding(rule, rel, f"'{key}' is not set in [{section}].",
                                  code_snippet=snippet)]
        snippet = self._snippet_for_key(text, section, key)
        if value.lower() in defaults:
            reason = "empty" if value == "" else f"a known default ('{value}')"
            return [self._finding(rule, rel, f"'{key}' is set to {reason}.",
                                  code_snippet=snippet)]
        if min_len and len(value) < min_len:
            return [self._finding(rule, rel,
                                  f"'{key}' is only {len(value)} characters; at least "
                                  f"{min_len} are recommended.",
                                  code_snippet=snippet)]
        return []

    # -- allowed_hosts ----------------------------------------------------- #
    def _check_allowed_hosts(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key", "allowed_hosts")
        value = get_value(sections, section, key)
        if value is None or value.strip() == "":
            snippet = self._snippet_missing_key(text, section, key) if value is None \
                else self._snippet_for_key(text, section, key)
            return [self._finding(rule, rel,
                                  "'allowed_hosts' is empty, so OJS trusts the inbound Host "
                                  "header (Host header injection).",
                                  code_snippet=snippet)]
        if "*" in value:
            snippet = self._snippet_for_key(text, section, key)
            return [self._finding(rule, rel,
                                  f"'allowed_hosts' uses a wildcard ('{value}'); trusts arbitrary "
                                  f"Host headers.",
                                  code_snippet=snippet)]
        return []

    # -- bool_directive ---------------------------------------------------- #
    def _check_bool_directive(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key")
        secure = rule.params.get("secure_value")
        insecure = rule.params.get("insecure_value")
        value = get_value(sections, section, key)

        if value is None:
            return self._absent(rule, key, rel, secure, text=text, section=section)

        snippet = self._snippet_for_key(text, section, key)
        if insecure is not None:
            if _bool_equal(value, insecure):
                return [self._finding(rule, rel, f"'{key}' is set to '{value}' (insecure).",
                                      code_snippet=snippet)]
            return []
        if secure is not None and not _bool_equal(value, secure):
            return [self._finding(rule, rel,
                                  f"'{key}' is '{value}'; should be '{secure}'.",
                                  code_snippet=snippet)]
        return []

    # -- enum_directive ---------------------------------------------------- #
    def _check_enum_directive(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key")
        secure_values = {str(v).lower() for v in rule.params.get("secure_values", [])}
        value = get_value(sections, section, key)
        if value is None:
            return self._absent(rule, key, rel,
                                rule.params.get("default_when_absent"), secure_values,
                                text=text, section=section)
        if value.strip().lower() in secure_values:
            return []
        snippet = self._snippet_for_key(text, section, key)
        return [self._finding(rule, rel,
                              f"'{key}' is '{value}'; expected one of "
                              f"{sorted(rule.params.get('secure_values', []))}.",
                              code_snippet=snippet)]

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
                snippet = self._snippet_missing_key(text, section, key)
                return [self._finding(rule, rel, f"'{key}' is not set in [{section}].",
                                      severity=Severity.from_str(warn_sev),
                                      code_snippet=snippet)]

        try:
            val = int(value.strip())
        except (ValueError, AttributeError):
            snippet = self._snippet_for_key(text, section, key)
            return [self._finding(rule, rel, f"'{key}' has non-numeric value '{value}'.",
                                  code_snippet=snippet)]

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
        snippet = self._snippet_for_key(text, section, key)
        return [self._finding(rule, rel,
                              f"'{key}' is {val}; expected {operator} {threshold}.",
                              severity=Severity.from_str(warn_sev),
                              code_snippet=snippet)]

    # -- base_url_scheme --------------------------------------------------- #
    def _check_base_url_scheme(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key", "base_url")
        value = get_value(sections, section, key)
        findings: List[Finding] = []

        if value is None:
            snippet = self._snippet_missing_key(text, section, key)
            return [self._finding(rule, rel, f"'{key}' is not set.",
                                  code_snippet=snippet)]

        snippet = self._snippet_for_key(text, section, key)
        # Check placeholder values.
        placeholders = rule.params.get("placeholder_values", [])
        if value.strip().lower() in [p.lower() for p in placeholders]:
            findings.append(self._finding(rule, rel,
                                          f"'{key}' is still the default placeholder ('{value}').",
                                          code_snippet=snippet))

        # Check scheme.
        required = rule.params.get("required_scheme", "https")
        if value.strip().lower().startswith("http://"):
            findings.append(self._finding(rule, rel,
                                          f"'{key}' uses HTTP instead of HTTPS.",
                                          code_snippet=snippet))

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
            snippet = self._snippet_for_key(text, section, key)
            return [self._finding(rule, rel,
                                  f"'allowed_html' contains dangerous tag(s): {', '.join(found)}.",
                                  code_snippet=snippet)]
        return []

    # -- captcha_engine ---------------------------------------------------- #
    def _check_captcha_engine(self, rule, text, sections, rel) -> List[Finding]:
        captcha_sec = sections.get("captcha", {})
        recaptcha = captcha_sec.get("recaptcha", "off").strip().lower()
        altcha = captcha_sec.get("altcha", "off").strip().lower()

        if recaptcha in _TRUE_WORDS or altcha in _TRUE_WORDS:
            return []
        snippet = self._snippet_missing_key(text, "captcha", "recaptcha / altcha")
        return [self._finding(rule, rel,
                              "Neither reCAPTCHA nor ALTCHA is enabled in [captcha]. "
                              "No bot protection on registration/login.",
                              code_snippet=snippet)]

    # -- breached_password ------------------------------------------------- #
    def _check_breached_password(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "database")
        key = rule.params.get("key", "password")
        value = get_value(sections, section, key)
        if not value:
            return []
        breached = {str(p).lower() for p in rule.params.get("breached_passwords", [])}
        if value.lower() in breached:
            snippet = self._snippet_for_key(text, section, key)
            return [self._finding(rule, rel,
                                  "The database password matches a common/breached password.",
                                  code_snippet=snippet)]
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
                snippet = self._snippet_for_key(text, section, key)
                return [self._finding(rule, rel,
                                      f"The database password equals the database {cmp_key} "
                                      f"('{other}').",
                                      code_snippet=snippet)]
        return []

    # -- informational_directive ------------------------------------------- #
    def _check_informational_directive(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "general")
        key = rule.params.get("key")
        val = get_value(sections, section, key)
        snippet = self._snippet_for_key(text, section, key) if val is not None else self._snippet_missing_key(text, section, key)
        
        detail = f"Informational: '{key}' in [{section}] is set to '{val}'." if val is not None else f"Informational: '{key}' is not set in [{section}]."
        
        extra = {"do_not_flag": True, "informational": True}
        return [self._finding(rule, rel, detail, severity=Severity.INFO, code_snippet=snippet, extra=extra)]

    # -- default_db_credentials --------------------------------------------- #
    def _check_default_db_credentials(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "database")
        username = get_value(sections, section, "username") or ""
        password = get_value(sections, section, "password") or ""
        dbname = get_value(sections, section, "name") or ""

        username = username.strip()
        password = password.strip()
        dbname = dbname.strip()

        reasons = []

        # 1. username/password default seperti ojs/ojs
        if username.lower() == "ojs" and password.lower() == "ojs":
            reasons.append("default username/password (ojs/ojs) used")

        # 2. fail jika password lemah, kosong, root, password, ojs
        weak_set = {"", "root", "password", "ojs", "changeme", "database", "mysql", "123456", "12345678", "admin", "secret"}
        if password.lower() in weak_set:
            reasons.append(f"password is weak or empty ('{password}')")
        elif len(password) < 6:
            reasons.append(f"password is too short ({len(password)} chars; minimum 6 required)")
        elif password.lower() == username.lower() or password.lower() == dbname.lower():
            reasons.append("password is identical to username or database name")

        if reasons:
            snippet = self._snippet_for_key(text, section, "password")
            return [self._finding(
                rule, rel,
                f"Weak database credentials detected: {'; '.join(reasons)}.",
                code_snippet=snippet
            )]
        return []

    # -- db_secure_remote --------------------------------------------------- #
    def _check_db_secure_remote(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "database")
        host = get_value(sections, section, "host")
        secure = get_value(sections, section, "secure")
        unix_socket = get_value(sections, section, "unix_socket")

        # host local check
        is_local = False
        if host:
            h_clean = host.strip().lower()
            if h_clean in ("localhost", "127.0.0.1"):
                is_local = True
        else:
            is_local = True

        has_unix_socket = bool(unix_socket and unix_socket.strip())
        is_secure = _as_bool(secure) is True

        if is_local or has_unix_socket or is_secure:
            return []

        snippet = self._snippet_for_key(text, section, "host")
        return [self._finding(
            rule, rel,
            f"Database host '{host}' is remote and secure connection (SSL/TLS) is not enabled.",
            code_snippet=snippet
        )]

    # -- files_dir_webroot ------------------------------------------------- #
    def _check_files_dir_webroot(self, rule, text, sections, rel) -> List[Finding]:
        section = rule.params.get("section", "files")
        key = rule.params.get("key", "files_dir")
        value = get_value(sections, section, key)
        if not value:
            return []
        snippet = self._snippet_for_key(text, section, key)
        p = Path(value)
        if not p.is_absolute():
            return [self._finding(rule, rel,
                                  f"'files_dir' is a relative path ('{value}'), resolving inside "
                                  f"the OJS web root.",
                                  code_snippet=snippet)]
        if self.ojs_path:
            try:
                fd = p.resolve()
                root = self.ojs_path.resolve()
                if fd == root or root in fd.parents:
                    return [self._finding(rule, rel,
                                          f"'files_dir' ('{value}') is inside the OJS install/web "
                                          f"root ({root}).",
                                          code_snippet=snippet)]
            except OSError:  # pragma: no cover
                pass
        return []

    # -- absent directive helper ------------------------------------------- #
    def _absent(self, rule, key, rel, secure_value, secure_set=None,
               *, text: str = "", section: str = "") -> List[Finding]:
        """Handle an absent directive, honoring secure-by-default versions."""
        default = rule.params.get("default_when_absent")
        is_secure_default = False
        if default is not None:
            if secure_set is not None:
                is_secure_default = str(default).lower() in secure_set
            elif secure_value is not None:
                is_secure_default = _bool_equal(str(default), str(secure_value))
        snippet = self._snippet_missing_key(text, section or rule.params.get("section", "general"), key) if text else ""
        if is_secure_default:
            absent_sev = rule.params.get("absent_severity")
            if not absent_sev:
                return []
            since = rule.params.get("default_since")
            note = f" (default '{default}' since OJS {since})" if since else f" (default '{default}')"
            return [self._finding(rule, rel,
                                  f"'{key}' is not set; relying on the secure default{note}.",
                                  severity=Severity.from_str(absent_sev),
                                  code_snippet=snippet)]
        return [self._finding(rule, rel,
                              f"'{key}' is not set; the default '{default}' is insecure.",
                              code_snippet=snippet)]

    # -- Nginx --------------------------------------------------------------- #
    def _load_nginx(self, nginx_paths: Optional[List[Path]]) -> List[Tuple[str, str]]:
        """Load nginx configs as a list of ``(text, label)`` per file."""
        if not nginx_paths:
            return []
        result: List[Tuple[str, str]] = []
        for p in nginx_paths:
            p = Path(p)
            files: List[Path] = []
            if p.is_dir():
                files = [f for f in sorted(p.rglob("*")) if f.is_file()]
            elif p.is_file():
                files = [p]
            for f in files:
                try:
                    result.append((f.read_text(encoding="utf-8", errors="replace"), str(f)))
                except OSError:  # pragma: no cover
                    continue
        return result

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
        snippet = build_missing_evidence_snippet(text, None, "upload PHP deny block")
        return [self._finding(rule, label,
                              "No Nginx rule denies access/execution under the uploads "
                              "(files/public) directory.",
                              code_snippet=snippet)]

    def _check_nginx_security_headers(self, rule, text, label) -> List[Finding]:
        findings: List[Finding] = []
        low = text.lower()
        for header in rule.params.get("required_headers", []):
            if header.lower() not in low:
                snippet = build_missing_evidence_snippet(text, None, f"header: {header}")
                findings.append(self._finding(
                    rule, label,
                    f"Security header '{header}' is not configured.",
                    severity=rule.severity,
                    dedup_discriminator=header,
                    extra={"header": header},
                    code_snippet=snippet,
                ))
        return findings

    def _check_nginx_server_tokens(self, rule, text, label) -> List[Finding]:
        if re.search(r"server_tokens\s+off\s*;", text, re.IGNORECASE):
            return []
        snippet = build_missing_evidence_snippet(text, None, "server_tokens off")
        return [self._finding(rule, label, "'server_tokens off;' is not set; Nginx leaks its version.",
                              code_snippet=snippet)]

    def _check_nginx_autoindex(self, rule, text, label) -> List[Finding]:
        m = re.search(r"autoindex\s+on\s*;", text, re.IGNORECASE)
        if m:
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = build_code_snippet(text, line_no)
            return [self._finding(rule, label, "'autoindex on;' enables directory listing.",
                                  code_snippet=snippet)]
        return []
