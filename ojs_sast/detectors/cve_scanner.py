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
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..helpers.snippet_utils import build_code_snippet
from ..helpers.path_utils import matches_cve_path
from ..helpers.php_utils import (
    extract_class_body,
    extract_function_body,
    find_all_pattern_lines,
    find_all_pattern_spans,
    find_pattern_line,
    find_pattern_span,
    find_request_variables,
    find_unserialize_sinks,
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
# File-walking configuration (the CVE scanner is now the source_code module).
# --------------------------------------------------------------------------- #
PHP_EXTENSIONS = {".php", ".phtml", ".inc", ".php3", ".php4", ".php5"}
SMARTY_EXTENSIONS = {".tpl", ".smarty"}
JS_EXTENSIONS = {".js", ".jsx"}
SCANNED_EXTENSIONS = PHP_EXTENSIONS | SMARTY_EXTENSIONS | JS_EXTENSIONS

DEFAULT_SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "bower_components",
    "__pycache__", ".idea", ".vscode",
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# A function_name / class_name value meaning "no scope restriction".
_WILDCARD_SCOPE = {None, "", "*"}


def _collect_scope_names(
    params: Dict[str, Any], single_key: str, list_key: str,
) -> List[str]:
    """Merge a singular + plural ruleset scope key into one ordered name list.

    A rule may pin a scope with either a single value (``function_name: init``)
    or — to cover OJS versions that renamed the symbol — a list of alternatives
    (``function_names: [init, initPlugin]``). Both forms are honoured for
    ``function_name(s)`` and ``class_name(s)`` and treated as OR alternatives.
    The singular value is tried first so existing single-name rules keep their
    exact prior behaviour.

    Wildcard / empty sentinels (``*``, ``""``, ``None``) carry no concrete name
    and are dropped, so an all-wildcard scope yields ``[]`` (no restriction).
    Order is preserved and duplicates removed.
    """
    names: List[str] = []
    single = params.get(single_key)
    if single is not None and single not in _WILDCARD_SCOPE:
        names.append(str(single))
    for raw in params.get(list_key, []) or []:
        if raw is None or raw in _WILDCARD_SCOPE:
            continue
        name = str(raw)
        if name not in names:
            names.append(name)
    return names


# --------------------------------------------------------------------------- #
# CVE Scanner Engine
# --------------------------------------------------------------------------- #
class CVEScanner:
    """Evaluates the structured ``cve_rules.yaml`` rules against source files.

    This is the ``source_code`` module scanner: it walks the OJS tree and runs
    every source-code rule that declares a ``vulnerability_type`` (CVE rules plus
    the generic structured rules such as ``SAST-SRC-LESS-001``). Each rule is
    routed to the detector that matches its ``vulnerability_type`` and only emits
    a finding when path, scope, source, sink, missing-safe-patch and OJS version
    conditions all hold.
    """

    def __init__(
        self,
        ruleset: Ruleset,
        ojs_version: Optional[str] = None,
        *,
        verbose: bool = False,
        progress_cb: Optional[Callable[[str], None]] = None,
        skip_dirs: Optional[Sequence[str]] = None,
    ):
        self.ojs_version = ojs_version
        self.verbose = verbose
        self.progress_cb = progress_cb
        self.skip_dirs = set(skip_dirs) if skip_dirs else set(DEFAULT_SKIP_DIRS)
        self.files_scanned = 0
        # Structured source-code rules driven by cve_rules.yaml. A rule qualifies
        # when it targets the source_code module and declares a vulnerability_type
        # (covers both pattern_type: cve and the generic structured regex rules).
        self.cve_rules: List[Rule] = [
            r for r in ruleset
            if r.module == "source_code" and r.params.get("vulnerability_type")
        ]
        # Concrete detectors. ``_select_detector`` maps a (possibly descriptive)
        # vulnerability_type string onto one of these.
        self._sqli = _SQLiDetector()
        self._csrf = _CSRFDetector()
        self._path_traversal = _PathTraversalDetector()
        self._code_injection = _CodeInjectionDetector()
        self._smarty_xss = _SmartyXSSDetector()
        self._php_xss = _PHPXSSDetector()
        self._host_header = _HostHeaderDetector()
        self._deserialization = _DeserializationDetector()

        # Surface rules whose vulnerability_type maps to no detector. Such a rule
        # loads cleanly but can never produce a finding, so a silently-dropped
        # rule (e.g. an unrecognised type from a converted ruleset) would otherwise
        # look like a false negative. Reported once at init instead of per-file.
        self.unroutable_rules: List[Tuple[str, str]] = []
        for r in self.cve_rules:
            vt = r.params.get("vulnerability_type", "")
            if self._select_detector(vt, "probe.php") is None:
                self.unroutable_rules.append((r.id, str(vt)))
                logger.warning(
                    "CVE rule %s: vulnerability_type %r is not recognised by any "
                    "detector; this rule will never produce findings", r.id, vt,
                )

    # ------------------------------------------------------------------ #
    # Detector dispatch
    # ------------------------------------------------------------------ #
    def _select_detector(self, vuln_type: str, rel: str) -> Optional["_BaseDetector"]:
        """Route a ``vulnerability_type`` to a detector.

        The ruleset uses descriptive types (``reflected_xss``,
        ``path_traversal_arbitrary_file_write_rce``,
        ``host_header_injection_reflected_xss`` …), so matching is keyword-based.
        XSS is split between Smarty templates and PHP by file extension.
        Ordering matters: host-header and deserialization are checked before the
        generic ``xss`` keyword.
        """
        vt = (vuln_type or "").lower()
        if not vt:
            return None
        if "sqli" in vt or "sql_injection" in vt:
            return self._sqli
        if "csrf" in vt:
            return self._csrf
        if "deserial" in vt:
            return self._deserialization
        if "host_header" in vt:
            return self._host_header
        if "path_traversal" in vt or "file_write" in vt:
            return self._path_traversal
        if "less" in vt or "code_injection" in vt or "code_exec" in vt:
            return self._code_injection
        if "xss" in vt:
            if rel.lower().endswith((".tpl", ".smarty")):
                return self._smarty_xss
            return self._php_xss
        return None

    def scan_file(
        self, path: Path, rel: str, raw: bytes, text: Optional[str] = None,
    ) -> List[Finding]:
        """Evaluate all structured source-code rules against a single file.

        Only rules whose ``file_path_patterns`` match ``rel`` are evaluated.
        """
        findings: List[Finding] = []
        if text is None:
            text = raw.decode("utf-8", "replace")

        for rule in self.cve_rules:
            params = rule.params
            file_patterns = params.get("file_path_patterns", [])
            if not file_patterns:
                logger.debug("CVE %s: no file_path_patterns defined, skipping", rule.id)
                continue

            if not matches_cve_path(rel, file_patterns):
                logger.debug("CVE %s: path '%s' does not match %s", rule.id, rel, file_patterns)
                continue

            vuln_type = params.get("vulnerability_type", "")
            detector = self._select_detector(vuln_type, rel)
            if detector is None:
                logger.debug("CVE %s: no detector for vulnerability_type '%s'", rule.id, vuln_type)
                continue

            logger.debug("CVE %s: evaluating '%s' with detector '%s'", rule.id, rel, vuln_type)
            result = detector.evaluate(rule, rel, text, self.ojs_version)
            if result is not None:
                logger.debug("CVE %s: FINDING emitted for '%s'", rule.id, rel)
                findings.append(result)
            else:
                logger.debug("CVE %s: no finding for '%s'", rule.id, rel)

        return findings

    # ------------------------------------------------------------------ #
    # Directory walking (source_code module entry point)
    # ------------------------------------------------------------------ #
    def _progress(self, msg: str) -> None:
        if self.progress_cb:
            self.progress_cb(msg)

    def iter_files(self, root: Path):
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            if any(part in self.skip_dirs for part in path.parts):
                continue
            if path.suffix.lower() not in SCANNED_EXTENSIONS:
                continue
            yield path

    def scan(self, root_path) -> List[Finding]:
        """Walk ``root_path`` and evaluate the CVE ruleset over every source file."""
        root = Path(root_path)
        findings: List[Finding] = []
        for path in self.iter_files(root):
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    logger.debug("Skipping large file %s", path)
                    continue
                raw = path.read_bytes()
            except OSError as exc:  # pragma: no cover
                logger.warning("Cannot read %s: %s", path, exc)
                continue
            if b"\x00" in raw[:4096]:  # binary heuristic
                continue
            try:
                rel = str(path.relative_to(root))
            except ValueError:  # pragma: no cover
                rel = str(path)
            rel = rel.replace("\\", "/")
            self.files_scanned += 1
            if self.verbose:
                self._progress(f"source: {rel}")
            findings.extend(self.scan_file(path, rel, raw))
        logger.info("CVE scan complete: %d files, %d findings", self.files_scanned, len(findings))
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

        Each pattern is first matched line-by-line (the fast path, which keeps the
        original snippet/line behaviour). If that misses, a multiline DOTALL search
        is attempted so a pattern whose match legitimately spans several lines —
        e.g. a function call broken across lines like
        ``setServerFileName(\\n    $o->textContent\\n)`` — is still detected. The
        previous line-only behaviour silently missed every multi-line construct,
        diverging from structural matchers such as Semgrep.
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
            # Multiline fallback: the pattern may span lines (whitespace/newlines
            # between tokens). Only reached when the line-by-line search missed, so
            # single-line matches keep their exact prior line/snippet.
            span = find_pattern_span(text, pat, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if span:
                snippet = (span.snippet or "").splitlines()[0].strip() if span.snippet else ""
                line_no = span.line_start
                if scope:
                    base = source.find(scope)
                    if base != -1:
                        line_no = source.count("\n", 0, base) + span.line_start
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
        # A CVE finding is only emitted once the affected-version check passes, so
        # it is by definition applicable to the scanned version. The branch-aware
        # reasoning is carried in ``affected_version_reasoning`` as well.
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
            applicable=True,
            applicability_reason=f"applicable: {version_reasoning}",
            code_snippet=code_snip,
            confidence=confidence,
            matched_source=matched_source,
            matched_sink=matched_sink,
            missing_patch_evidence=missing_patch_evidence,
            safe_patch_checked=safe_patch_checked,
            affected_version_reasoning=version_reasoning,
            confidence_reason=confidence_reason,
        )

    @staticmethod
    def _resolve_function_scope(
        source: str, params: Dict[str, Any],
    ) -> Tuple[Optional[str], bool]:
        """Resolve an optional function scope honouring alternative names.

        Reads both ``function_name`` (str) and ``function_names`` (list) and
        treats them as OR alternatives, so a single rule can span OJS versions
        that renamed the function. Returns ``(scope, bail)``:
        * no concrete names (all wildcard / missing) → ``(None, False)``: analyse
          the whole file, no scope restriction;
        * at least one alternative exists in the file → ``(body, False)``;
        * concrete names given but NONE present → ``(None, True)`` so the caller
          can bail out (the rule targets a function this file lacks).
        """
        names = _collect_scope_names(params, "function_name", "function_names")
        if not names:
            return None, False
        for name in names:
            body = extract_function_body(source, name)
            if body is not None:
                return body, False
        return None, True

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
        scope, bail = self._resolve_function_scope(source, rule.params)
        if bail:
            return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _CSRFDetector(_BaseDetector):
    """Detect CSRF CVEs (e.g. CVE-2025-67892, CVE-2023-5626)."""

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params
        # class_name(s) / function_name(s) are OR alternatives so a rule still
        # applies to OJS versions that renamed the class or method. A wildcard
        # ("*") class/function contributes no name and so imposes no restriction
        # (previously a "*" class_name wrongly bailed out with no finding).
        class_names = _collect_scope_names(params, "class_name", "class_names")
        fn_names = _collect_scope_names(params, "function_name", "function_names")

        scope = None
        matched_class: Optional[str] = None
        matched_fn: Optional[str] = None
        base = source

        if class_names:
            for cn in class_names:
                class_body = extract_class_body(source, cn)
                if class_body is not None:
                    base, matched_class = class_body, cn
                    break
            if matched_class is None:
                return None  # none of the alternative classes are present
            scope = base

        if fn_names:
            for fn in fn_names:
                fn_body = extract_function_body(base, fn)
                if fn_body is not None:
                    scope, matched_fn = fn_body, fn
                    break
            if matched_fn is None:
                return None  # none of the alternative functions are present

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

        # Find the function/class declaration line for the finding, using the
        # alternative that actually matched.
        label = matched_fn or matched_class
        if matched_fn:
            decl_pattern = r"function\s+" + re.escape(matched_fn)
        elif matched_class:
            decl_pattern = r"class\s+" + re.escape(matched_class)
        else:
            decl_pattern = None
        fn_line_info = (
            find_pattern_line(source, decl_pattern, re.IGNORECASE)
            if decl_pattern else None
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
            matched_source=f"function {label}" if label else "CSRF-protected operation",
            matched_sink=f"Missing CSRF check in {label}" if label else "Missing CSRF check",
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
        scope, bail = self._resolve_function_scope(source, rule.params)
        if bail:
            return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _CodeInjectionDetector(_BaseDetector):
    """Detect code injection CVEs (e.g. CVE-2025-67893 LESS injection).

    Used by both the specific LESS CVE (``function_name: init``) and the generic
    ``SAST-SRC-LESS-001`` rule (``function_name: "*"`` → whole-file scope).
    """

    def evaluate(self, rule, rel, source, ojs_version):
        scope, bail = self._resolve_function_scope(source, rule.params)
        if bail:
            return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _SmartyXSSDetector(_BaseDetector):
    """Detect Smarty template XSS CVEs (e.g. CVE-2025-13469, CVE-2023-5903).

    Uses DOTALL multiline matching so Smarty tags and HTML attributes that span
    multiple lines are correctly detected.

    When any sink pattern carries an inline negative lookahead (``(?!``) the rule
    is doing *per-candidate* escape checking, so the file-level safe_patch check
    is skipped — otherwise an escaped expression elsewhere in the same template
    would wrongly suppress a genuine unescaped sink.
    """

    @staticmethod
    def _has_inline_escape_guard(rule: Rule) -> bool:
        return any("(?!" in p for p in rule.params.get("sink_patterns", []))

    def evaluate(self, rule, rel, source, ojs_version):
        if self._has_inline_escape_guard(rule):
            return self._evaluate_no_file_safe_patch(rule, rel, source, ojs_version)
        return self._evaluate_generic_smarty_xss(rule, rel, source, ojs_version)

    def _evaluate_no_file_safe_patch(self, rule, rel, source, ojs_version):
        """Evaluate without file-level safe_patch; sink patterns carry inline negative lookahead."""
        params = rule.params
        affected, version_reason = is_version_affected(
            ojs_version,
            params.get("affected_versions"),
            params.get("patched_versions"),
        )
        if not affected:
            logger.debug("CVE %s: version %s not in affected range", rule.id, ojs_version)
            return None

        sink_patterns = params.get("sink_patterns", [])
        source_patterns = params.get("source_patterns", [])

        for pat in sink_patterns:
            hit = find_pattern_span(source, pat, re.IGNORECASE | re.DOTALL | re.MULTILINE)
            if hit:
                logger.debug(
                    "CVE %s: sink pattern matched at line %d (snippet: %r)",
                    rule.id, hit.line_start, (hit.snippet or "")[:80],
                )
                src_pat = source_patterns[0] if source_patterns else pat
                confidence = "high" if ojs_version else "medium"
                conf_reason = params.get("confidence_reason", "")
                if not ojs_version:
                    conf_reason += " (version unknown — confidence reduced)"
                return self._make_finding(
                    rule=rule,
                    rel=rel,
                    line=hit.line_start,
                    snippet=hit.snippet or "",
                    matched_source=src_pat,
                    matched_sink=pat,
                    missing_patch_evidence="Inline negative lookahead applied — no file-level safe-patch",
                    safe_patch_checked=[],
                    version_reasoning=version_reason,
                    confidence=confidence,
                    confidence_reason=conf_reason,
                    source_text=source,
                )

        logger.debug("CVE %s: no sink pattern matched in %s", rule.id, rel)
        return None

    def _evaluate_generic_smarty_xss(self, rule, rel, source, ojs_version):
        """Standard Smarty XSS evaluation with file-level safe_patch check."""
        params = rule.params

        # 1) Version check.
        affected, version_reason = is_version_affected(
            ojs_version,
            params.get("affected_versions"),
            params.get("patched_versions"),
        )
        if not affected:
            logger.debug("CVE %s: version %s not in affected range", rule.id, ojs_version)
            return None

        # 2) Safe-patch patterns at file level.
        is_patched, checked = self._check_safe_patches(
            source, params.get("safe_patch_patterns", [])
        )
        if is_patched:
            logger.debug("CVE %s: safe patch pattern found at file level", rule.id)
            return None

        # 3) Sink patterns with DOTALL multiline matching.
        sink_patterns = params.get("sink_patterns", [])
        source_patterns = params.get("source_patterns", [])

        for pat in sink_patterns:
            hit = find_pattern_span(
                source, pat,
                re.IGNORECASE | re.DOTALL | re.MULTILINE,
            )
            if hit:
                logger.debug(
                    "CVE %s: sink pattern matched at line %d (snippet: %r)",
                    rule.id, hit.line_start, (hit.snippet or "")[:80],
                )
                src_pat = source_patterns[0] if source_patterns else pat
                confidence = "high" if ojs_version else "medium"
                conf_reason = params.get("confidence_reason", "")
                if not ojs_version:
                    conf_reason += " (version unknown — confidence reduced)"

                return self._make_finding(
                    rule=rule,
                    rel=rel,
                    line=hit.line_start,
                    snippet=hit.snippet or "",
                    matched_source=src_pat,
                    matched_sink=pat,
                    missing_patch_evidence=f"Safe patterns not found: {checked}",
                    safe_patch_checked=checked,
                    version_reasoning=version_reason,
                    confidence=confidence,
                    confidence_reason=conf_reason,
                    source_text=source,
                )

        logger.debug("CVE %s: no sink pattern matched in %s", rule.id, rel)
        return None


class _PHPXSSDetector(_BaseDetector):
    """Detect PHP-level XSS CVEs (e.g. CVE-2023-5894)."""

    def evaluate(self, rule, rel, source, ojs_version):
        return self._standard_evaluate(rule, rel, source, ojs_version)


class _HostHeaderDetector(_BaseDetector):
    """Detect Host header injection CVEs (e.g. CVE-2022-26616)."""

    def evaluate(self, rule, rel, source, ojs_version):
        scope, bail = self._resolve_function_scope(source, rule.params)
        if bail:
            return None
        return self._standard_evaluate(rule, rel, source, ojs_version, scope)


class _DeserializationDetector(_BaseDetector):
    """Detect unsafe deserialization CVEs (e.g. CVE-2019-19909).

    Evaluation order: function body → class body → full file.
    Safe-patch check is scoped to the same text as source/sink search so that
    json_decode() in an unrelated function does not suppress the finding.

    Detection combines the rule's literal sink patterns with a small intra-file
    dataflow pass (request var → unserialize) so both the inline and the
    two-step forms of the vulnerability are caught.
    """

    @staticmethod
    def _dataflow_sink(
        full_source: str, scope_text: str
    ) -> Optional[Tuple[str, int, str]]:
        """Find a request-controlled value reaching ``unserialize()``.

        Resolves variables assigned from ``getUserVar('param')`` inside
        ``scope_text`` and checks whether any of them are later passed to
        ``unserialize()`` (optionally wrapped in ``base64_decode``). Returns
        ``(matched_sink, line_in_full_source, snippet)`` or ``None``.
        """
        params_found = set(
            re.findall(r"getUserVar\s*\(\s*['\"](\w+)['\"]", scope_text, re.IGNORECASE)
        )
        if not params_found:
            return None
        req_vars = find_request_variables(scope_text, params_found)
        if not req_vars:
            return None
        sinks = find_unserialize_sinks(scope_text, set(req_vars.keys()))
        if not sinks:
            return None

        sinks.sort(key=lambda s: s.line_start)  # deterministic: first sink wins
        sink = sinks[0]
        snippet = (sink.snippet or "").strip()
        # Map the snippet back to a line number in the full source for reporting.
        line_no = sink.line_start
        first_line = snippet.split("\n", 1)[0]
        if first_line:
            for i, line in enumerate(full_source.splitlines(), 1):
                if first_line in line:
                    line_no = i
                    break
        return f"unserialize() of request-controlled value (dataflow): {snippet}", line_no, snippet

    def evaluate(self, rule, rel, source, ojs_version):
        params = rule.params

        # 1) Version check.
        affected, version_reason = is_version_affected(
            ojs_version,
            params.get("affected_versions"),
            params.get("patched_versions"),
        )
        if not affected:
            logger.debug("CVE %s: version %s not in affected range", rule.id, ojs_version)
            return None

        # 2) Determine analysis scope: function → class → full file.
        #    function_name(s) and class_name(s) are OR alternatives so the rule
        #    spans OJS versions that renamed the symbol. Deserialization stays
        #    lenient: when no named scope matches it falls back to full-file +
        #    dataflow rather than bailing.
        fn_names = _collect_scope_names(params, "function_name", "function_names")
        class_names = _collect_scope_names(params, "class_name", "class_names")
        scope: Optional[str] = None
        scope_label = "full file"

        for name in fn_names:
            s = extract_function_body(source, name)
            if s:
                scope = s
                scope_label = f"function {name}"
                logger.debug("CVE %s: using function scope '%s'", rule.id, name)
                break

        if not scope:
            if fn_names:
                logger.debug(
                    "CVE %s: none of %s found, trying class/full-file scope",
                    rule.id, fn_names,
                )
            for cn in class_names:
                cb = extract_class_body(source, cn)
                if cb:
                    scope = cb
                    scope_label = f"class {cn}"
                    logger.debug("CVE %s: using class scope '%s'", rule.id, cn)
                    break
            if not scope:
                if class_names:
                    logger.debug(
                        "CVE %s: none of classes %s found, falling back to full file",
                        rule.id, class_names,
                    )
                else:
                    logger.debug("CVE %s: no function/class scope, using full file", rule.id)

        check_text = scope if scope else source

        # 3) Scope-aware safe-patch check (prevents json_decode in another
        #    function from suppressing a finding in generateReport).
        is_patched, checked = self._check_safe_patches(
            check_text, params.get("safe_patch_patterns", [])
        )
        if is_patched:
            logger.debug("CVE %s: safe patch found in scope (%s)", rule.id, scope_label)
            return None

        # 4) Source patterns.
        source_hit = self._check_source_patterns(source, params.get("source_patterns", []), scope)
        if source_hit is None:
            logger.debug("CVE %s: source pattern not found in scope (%s)", rule.id, scope_label)
            return None
        src_pat, src_line, src_snippet = source_hit

        # 5) Sink: try the rule's literal sink patterns first (catches the
        #    inline `unserialize($request->getUserVar(...))` form). If none match,
        #    fall back to intra-file dataflow so the realistic two-step form
        #    (`$x = getUserVar('filters'); ... unserialize($x);`) is still caught.
        sink_hit = self._check_sink_patterns(source, params.get("sink_patterns", []), scope)
        if sink_hit is not None:
            sink_pat, sink_line, sink_snippet = sink_hit
        else:
            df = self._dataflow_sink(source, check_text)
            if df is None:
                logger.debug(
                    "CVE %s: no sink (literal or dataflow) in scope (%s)", rule.id, scope_label
                )
                return None
            sink_pat, sink_line, sink_snippet = df
            logger.debug("CVE %s: dataflow sink at line %d (%s)", rule.id, sink_line, scope_label)

        confidence = "high" if ojs_version else "medium"
        conf_reason = params.get("confidence_reason", "")
        if not ojs_version:
            conf_reason += f" (version unknown — confidence reduced; scope: {scope_label})"

        logger.debug(
            "CVE %s: FINDING — source line %d, sink line %d (scope: %s)",
            rule.id, src_line, sink_line, scope_label,
        )
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
