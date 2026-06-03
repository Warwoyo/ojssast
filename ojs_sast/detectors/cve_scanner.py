"""CVE-specific vulnerability scanner for OJS.

Evaluates structured, multi-condition rules from ``cve_rules.yaml``.
Each CVE rule checks: file path, class/function name, source/sink patterns,
absence of safe-patch patterns, and OJS version ranges.

Only emits findings when ALL conditions are met, producing high-confidence,
evidence-rich results tied to exactly one CVE.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..helpers.snippet_utils import build_code_snippet
from ..helpers.path_utils import matches_cve_path
from ..helpers.php_utils import (
    extract_class_body,
    extract_function_body,
    find_all_pattern_lines,
    find_pattern_line,
    has_pattern_in_function,
)
from ..helpers.smarty_utils import (
    find_html_attribute_variable,
    find_smarty_variable,
    find_translate_tag,
)
from ..helpers.version_utils import is_version_affected
from ..models import Finding, Rule, Severity, resolve_rule_metadata
from ..ruleset.loader import Ruleset

logger = logging.getLogger("ojs_sast.cve_scanner")


# --------------------------------------------------------------------------- #
# CVE Scanner Engine
# --------------------------------------------------------------------------- #
class CVEScanner:
    """Evaluates CVE-specific rules against scanned source files."""

    def __init__(
        self,
        ruleset: Ruleset,
        ojs_version: Optional[str] = None,
    ):
        self.ojs_version = ojs_version
        # Filter to only CVE pattern-type rules.
        self.cve_rules: List[Rule] = [
            r for r in ruleset if r.pattern_type == "cve"
        ]
        # Index rules by vulnerability type for efficient dispatch.
        self._detectors: Dict[str, _BaseDetector] = {
            "sqli": _SQLiDetector(),
            "csrf": _CSRFDetector(),
            "path_traversal": _PathTraversalDetector(),
            "code_injection": _CodeInjectionDetector(),
            "smarty_xss": _SmartyXSSDetector(),
            "php_xss": _PHPXSSDetector(),
            "host_header": _HostHeaderDetector(),
            "deserialization": _DeserializationDetector(),
        }

    def scan_file(
        self, path: Path, rel: str, raw: bytes, text: Optional[str] = None,
    ) -> List[Finding]:
        """Evaluate all CVE rules against a single file.

        Only rules whose ``file_path_patterns`` match ``rel`` are evaluated.
        """
        findings: List[Finding] = []
        if text is None:
            text = raw.decode("utf-8", "replace")

        for rule in self.cve_rules:
            params = rule.params
            file_patterns = params.get("file_path_patterns", [])
            if not file_patterns:
                continue

            if not matches_cve_path(rel, file_patterns):
                continue

            vuln_type = params.get("vulnerability_type", "")
            detector = self._detectors.get(vuln_type)
            if detector is None:
                logger.debug("No detector for type %s (rule %s)", vuln_type, rule.id)
                continue

            result = detector.evaluate(rule, rel, text, self.ojs_version)
            if result is not None:
                findings.append(result)

        return findings


# --------------------------------------------------------------------------- #
# Base Detector
# --------------------------------------------------------------------------- #
class _BaseDetector:
    """Base class for CVE-specific detectors."""

    def evaluate(
        self, rule: Rule, rel: str, source: str, ojs_version: Optional[str],
    ) -> Optional[Finding]:
        """Evaluate the rule against ``source``.  Return a Finding or None."""
        raise NotImplementedError

    # -- shared helpers ---------------------------------------------------- #

    @staticmethod
    def _check_source_patterns(
        source: str, patterns: List[str], scope: Optional[str] = None,
    ) -> Optional[Tuple[str, int, str]]:
        """Search for any of ``patterns`` in ``source`` (or ``scope``).

        Returns (matched_pattern, line_number, snippet) or None.
        """
        text = scope if scope else source
        for pat in patterns:
            match = find_pattern_line(text, pat, re.IGNORECASE)
            if match:
                line_no, snippet = match
                if scope:
                    # Adjust line number relative to full source.
                    for i, line in enumerate(source.splitlines(), 1):
                        if snippet in line:
                            line_no = i
                            break
                return pat, line_no, snippet
        return None

    @staticmethod
    def _check_sink_patterns(
        source: str, patterns: List[str], scope: Optional[str] = None,
    ) -> Optional[Tuple[str, int, str]]:
        """Same as _check_source_patterns but for sinks."""
        return _BaseDetector._check_source_patterns(source, patterns, scope)

    @staticmethod
    def _check_safe_patches(
        source: str, patterns: List[str], scope: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Check if any safe-patch pattern is present.

        Returns (is_patched, checked_patterns).
        """
        text = scope if scope else source
        checked = []
        for pat in patterns:
            checked.append(pat)
            if re.search(pat, text, re.IGNORECASE):
                return True, checked
        return False, checked

    @staticmethod
    def _make_finding(
        rule: Rule,
        rel: str,
        line: int,
        snippet: str,
        matched_source: str,
        matched_sink: str,
        missing_patch_evidence: str,
        safe_patch_checked: List[str],
        version_reasoning: str,
        confidence: str,
        confidence_reason: str,
        source_text: str = "",
    ) -> Finding:
        code_snip = build_code_snippet(source_text, line) if source_text else snippet
        return Finding(
            rule_id=rule.id,
            module="source_code",
            severity=rule.severity,
            file_path=rel,
            title=rule.name,
            detail=rule.description,
            remediation=rule.remediation,
            line=line,
            cwe=rule.cwe,
            owasp=rule.owasp,
            cvss_score=rule.cvss_score,
            cve_references=list(rule.cve_references),
            **resolve_rule_metadata(rule.id, rule.params),
            code_snippet=code_snip,
            confidence=confidence,
            matched_source=matched_source,
            matched_sink=matched_sink,
            missing_patch_evidence=missing_patch_evidence,
            safe_patch_checked=safe_patch_checked,
            affected_version_reasoning=version_reasoning,
            confidence_reason=confidence_reason,
        )

    def _standard_evaluate(
        self,
        rule: Rule,
        rel: str,
        source: str,
        ojs_version: Optional[str],
        scope: Optional[str] = None,
    ) -> Optional[Finding]:
        """Standard multi-condition evaluation used by most detectors."""
        params = rule.params

        # 1) Version check.
        affected, version_reason = is_version_affected(
            ojs_version,
            params.get("affected_versions"),
            params.get("patched_versions"),
        )
        if not affected:
            return None

        # 2) Source patterns.
        source_hit = self._check_source_patterns(
            source, params.get("source_patterns", []), scope
        )
        if source_hit is None:
            return None
        src_pat, _, _ = source_hit

        # 3) Sink patterns.
        sink_hit = self._check_sink_patterns(
            source, params.get("sink_patterns", []), scope
        )
        if sink_hit is None:
            return None
        sink_pat, sink_line, sink_snippet = sink_hit

        # 4) Safe-patch patterns (should be ABSENT for vulnerability).
        is_patched, checked = self._check_safe_patches(
            source, params.get("safe_patch_patterns", []), scope
        )
        if is_patched:
            return None

        # 5) Determine confidence.
        confidence = "high" if ojs_version else "medium"
        conf_reason = params.get("confidence_reason", "")
        if not ojs_version:
            conf_reason += " (version unknown — confidence reduced)"

        return self._make_finding(
            rule=rule,
            rel=rel,
            line=sink_line,
            snippet=sink_snippet,
            matched_source=src_pat,
            matched_sink=sink_pat,
            missing_patch_evidence=f"Safe patterns not found: {checked}",
            safe_patch_checked=checked,
            version_reasoning=version_reason,
            confidence=confidence,
            confidence_reason=conf_reason,
            source_text=source,
        )


# --------------------------------------------------------------------------- #
# Concrete Detectors
# --------------------------------------------------------------------------- #

class _SQLiDetector(_BaseDetector):
    """Detect SQL injection CVEs (e.g. CVE-2025-67889)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        fn_name = params.get("function_name")
        scope = None
        if fn_name:
            scope = extract_function_body(source, fn_name)
            if scope is None:
                return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _CSRFDetector(_BaseDetector):
    """Detect CSRF CVEs (e.g. CVE-2025-67892, CVE-2023-5626)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        class_name = params.get("class_name")
        fn_name = params.get("function_name")
        scope = None

        if class_name:
            class_body = extract_class_body(source, class_name)
            if class_body is None:
                return None
            if fn_name:
                scope = extract_function_body(class_body, fn_name)
                if scope is None:
                    return None
            else:
                scope = class_body

        # For CSRF, the "sink" is the state-changing operation.
        # The "safe patch" is the CSRF check.
        # Check if the safe-patch patterns are ABSENT.
        params_check = params.get("safe_patch_patterns", [])
        check_scope = scope if scope else source
        is_patched, checked = self._check_safe_patches(check_scope, params_check)
        if is_patched:
            return None

        # Version check.
        affected, version_reason = is_version_affected(
            ojs_version,
            params.get("affected_versions"),
            params.get("patched_versions"),
        )
        if not affected:
            return None

        # Find the function declaration line for the finding.
        fn_line_info = find_pattern_line(
            source,
            r"function\s+" + re.escape(fn_name) if fn_name else r"class\s+" + re.escape(class_name),
            re.IGNORECASE,
        )
        line_no = fn_line_info[0] if fn_line_info else 1
        snippet = fn_line_info[1] if fn_line_info else ""

        confidence = "high" if ojs_version else "medium"
        conf_reason = params.get("confidence_reason", "")
        if not ojs_version:
            conf_reason += " (version unknown — confidence reduced)"

        return self._make_finding(
            rule=rule,
            rel=rel,
            line=line_no,
            snippet=snippet,
            matched_source=f"function {fn_name or class_name}",
            matched_sink=f"Missing CSRF check in {fn_name or class_name}",
            missing_patch_evidence=f"Safe patterns not found: {checked}",
            safe_patch_checked=checked,
            version_reasoning=version_reason,
            confidence=confidence,
            confidence_reason=conf_reason,
            source_text=source,
        )


class _PathTraversalDetector(_BaseDetector):
    """Detect path traversal CVEs (e.g. CVE-2025-67890, CVE-2023-47271)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        fn_name = params.get("function_name")
        scope = None
        if fn_name:
            scope = extract_function_body(source, fn_name)
            if scope is None:
                # Try alternate function names from source patterns.
                return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _CodeInjectionDetector(_BaseDetector):
    """Detect code injection CVEs (e.g. CVE-2025-67893 LESS injection)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        fn_name = params.get("function_name")
        scope = None
        if fn_name:
            scope = extract_function_body(source, fn_name)
            if scope is None:
                return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _SmartyXSSDetector(_BaseDetector):
    """Detect Smarty template XSS CVEs (e.g. CVE-2025-13469, CVE-2023-5903)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params

        # Version check.
        affected, version_reason = is_version_affected(
            ojs_version,
            params.get("affected_versions"),
            params.get("patched_versions"),
        )
        if not affected:
            return None

        # Check safe-patch patterns first.
        is_patched, checked = self._check_safe_patches(
            source, params.get("safe_patch_patterns", [])
        )
        if is_patched:
            return None

        # Source + sink patterns — for Smarty, these are usually the same
        # (the variable IS the output sink in the template).
        sink_patterns = params.get("sink_patterns", [])
        for pat in sink_patterns:
            hit = find_pattern_line(source, pat, re.IGNORECASE)
            if hit:
                line_no, snippet = hit

                source_patterns = params.get("source_patterns", [])
                src_pat = source_patterns[0] if source_patterns else pat

                confidence = "high" if ojs_version else "medium"
                conf_reason = params.get("confidence_reason", "")
                if not ojs_version:
                    conf_reason += " (version unknown — confidence reduced)"

                return self._make_finding(
                    rule=rule,
                    rel=rel,
                    line=line_no,
                    snippet=snippet,
                    matched_source=src_pat,
                    matched_sink=pat,
                    missing_patch_evidence=f"Safe patterns not found: {checked}",
                    safe_patch_checked=checked,
                    version_reasoning=version_reason,
                    confidence=confidence,
                    confidence_reason=conf_reason,
                    source_text=source,
                )
        return None


class _PHPXSSDetector(_BaseDetector):
    """Detect PHP-level XSS CVEs (e.g. CVE-2023-5894)."""

    def evaluate(self, rule, rel, source, ojs_version):
        return self._standard_evaluate(rule, rel, source, ojs_version)


class _HostHeaderDetector(_BaseDetector):
    """Detect Host header injection CVEs (e.g. CVE-2022-26616)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        fn_name = params.get("function_name")
        scope = None
        if fn_name:
            scope = extract_function_body(source, fn_name)
            if scope is None:
                return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _DeserializationDetector(_BaseDetector):
    """Detect deserialization CVEs (e.g. CVE-2019-19909)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        fn_name = params.get("function_name")
        scope = None
        if fn_name:
            scope = extract_function_body(source, fn_name)
            # If function not found, fall back to full-file analysis.
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)
