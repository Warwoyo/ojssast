"""Upload-manifest scanner (service side).

Re-applies the five upload-directory detection layers to *manifest entries*
produced by the agent instead of reading upload files directly.  The agent
supplies only raw metadata (path, filename, extension, size, head_hex,
detected_mime); all signature matching (webshell, PDF markers) is performed
**service-side** from ``head_hex``.  This lets the SAST service flag malicious
uploads without ever receiving the upload files themselves — and without
requiring the agent to ship SAST core or ruleset code.

Findings produced here are compatible with those of the local
:class:`~ojs_sast.detectors.upload_scanner.UploadScanner` (same ``rule_id``,
``module``, ``layer``, ``severity``, ``actual_mime``, ``declared_extension`` and
``confidence``), so deduplication and reporting behave identically.

Pure stdlib — safe to import on a bare install (used by ``run_bundle``).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple

from ..models import Finding, Rule, Severity, resolve_rule_metadata
from ..ruleset.loader import Ruleset

logger = logging.getLogger("ojs_sast.upload_manifest")


@dataclass
class UploadLayerParams:
    """Resolved RULE-UPLOAD-001..005 parameters shared by the upload scanners."""

    r_ext: Optional[Rule]
    r_double: Optional[Rule]
    r_mime: Optional[Rule]
    r_shell: Optional[Rule]
    r_pdf: Optional[Rule]
    php_exts: Set[str]
    other_exts: Set[str]
    dangerous_exts: Set[str]
    php_mimes: Set[str]
    exec_mimes: Set[str]
    expected_mime: Dict[str, List[str]]
    shell_max: int
    signatures: List[Tuple[str, Pattern, str]]
    pdf_max: int
    pdf_keywords: List[Tuple[str, str]]


def load_upload_layer_params(ruleset: Ruleset) -> UploadLayerParams:
    """Resolve the upload-layer rule parameters.

    Mirrors ``UploadScanner.__init__`` exactly so both scanners derive identical
    extension / MIME / signature sets from the same ruleset (RULE-UPLOAD-001..005).
    """
    r_ext = ruleset.get("RULE-UPLOAD-001")
    r_double = ruleset.get("RULE-UPLOAD-002")
    r_mime = ruleset.get("RULE-UPLOAD-003")
    r_shell = ruleset.get("RULE-UPLOAD-004")
    r_pdf = ruleset.get("RULE-UPLOAD-005")

    p = r_ext.params if r_ext else {}
    php_exts = {e.lower() for e in p.get("php_extensions", [])}
    other_exts = {
        e.lower() for e in (
            p.get("server_extensions", []) + p.get("executable_extensions", [])
            + p.get("java_extensions", [])
        )
    }
    dangerous_exts = php_exts | other_exts

    mp = r_mime.params if r_mime else {}
    php_mimes = {m.lower() for m in mp.get("php_mimes", [])}
    exec_mimes = {m.lower() for m in mp.get("executable_mimes", [])}
    expected_mime = {k.lower(): [v.lower() for v in vs]
                     for k, vs in (mp.get("expected_mime", {}) or {}).items()}

    sp = r_shell.params if r_shell else {}
    shell_max = int(sp.get("max_bytes", 65536))
    flags = re.IGNORECASE if sp.get("case_insensitive", True) else 0
    signatures: List[Tuple[str, Pattern, str]] = []
    for sig in sp.get("signatures", []):
        try:
            signatures.append((sig.get("id", "?"),
                               re.compile(sig["pattern"], flags),
                               sig.get("detail", "")))
        except re.error as exc:  # pragma: no cover
            logger.error("Bad webshell signature %s: %s", sig.get("id"), exc)

    pp = r_pdf.params if r_pdf else {}
    pdf_max = int(pp.get("max_bytes", 1048576))
    pdf_keywords = [(k["token"], k.get("detail", "")) for k in pp.get("keywords", [])]

    return UploadLayerParams(
        r_ext=r_ext, r_double=r_double, r_mime=r_mime, r_shell=r_shell, r_pdf=r_pdf,
        php_exts=php_exts, other_exts=other_exts, dangerous_exts=dangerous_exts,
        php_mimes=php_mimes, exec_mimes=exec_mimes, expected_mime=expected_mime,
        shell_max=shell_max, signatures=signatures, pdf_max=pdf_max,
        pdf_keywords=pdf_keywords,
    )


def _head_bytes(entry: dict) -> bytes:
    """Decode ``head_hex`` from a manifest entry into raw bytes (empty on error)."""
    raw = entry.get("head_hex") or ""
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return b""


class UploadManifestScanner:
    """Scan upload *manifest entries* and emit upload-directory findings.

    Webshell signatures (layer 4) and PDF active-content markers (layer 5)
    are computed from the ``head_hex`` field in each entry — raw bytes from
    the file's header, encoded as a hex string by the agent. The scanner does
    NOT read pre-computed ``webshell_signature_matches`` or ``pdf_active_markers``
    fields; those are ignored if present for backward compatibility.
    """

    def __init__(self, ruleset: Ruleset, verbose: bool = False,
                 progress_cb: Optional[Callable[[str], None]] = None):
        self.ruleset = ruleset
        self.verbose = verbose
        self.progress_cb = progress_cb
        self.files_scanned = 0

        params = load_upload_layer_params(ruleset)
        self.r_ext = params.r_ext
        self.r_double = params.r_double
        self.r_mime = params.r_mime
        self.r_shell = params.r_shell
        self.r_pdf = params.r_pdf
        # Exposed for parity (drift-guard) tests vs UploadScanner.
        self.php_exts = params.php_exts
        self.other_exts = params.other_exts
        self.dangerous_exts = params.dangerous_exts
        self.php_mimes = params.php_mimes
        self.exec_mimes = params.exec_mimes
        self.expected_mime = params.expected_mime
        # Webshell signature patterns and PDF keyword tokens (used in layers 4/5).
        self.signatures = params.signatures
        self.pdf_keywords = params.pdf_keywords

    # ----------------------------------------------------------------- #
    def _progress(self, msg: str) -> None:
        if self.progress_cb:
            self.progress_cb(msg)

    @staticmethod
    def _head_bytes(entry: dict) -> bytes:
        """Decode ``head_hex`` from a manifest entry into raw bytes."""
        raw = entry.get("head_hex") or ""
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return b""

    def scan(self, manifest: Optional[List[Dict[str, Any]]]) -> List[Finding]:
        findings: List[Finding] = []
        for entry in manifest or []:
            if not isinstance(entry, dict) or entry.get("error"):
                continue
            rel = entry.get("path") or entry.get("filename") or ""
            name = entry.get("filename") or Path(rel).name
            ext = (entry.get("extension") or Path(name).suffix or "").lower()
            mime = entry.get("detected_mime")  # already lowercase from the builder
            self.files_scanned += 1
            if self.verbose:
                self._progress(f"manifest: {rel}")

            head = self._head_bytes(entry)

            # Layer 1: dangerous extension
            l1 = self._layer_dangerous_extension(rel, ext, mime)
            findings.extend(l1)

            # Layer 2: double extension
            findings.extend(self._layer_double_extension(rel, name, ext, mime))

            # Layer 3: MIME mismatch
            l3 = self._layer_mime_mismatch(rel, ext, mime)
            findings.extend(l3)

            # Layer 4: webshell signatures from head_hex bytes (gated).
            gate = bool(l1) or bool(l3) or (mime in self.php_mimes) or (mime in ("text/plain",))
            if gate:
                head = _head_bytes(entry)
                findings.extend(self._layer_webshell_from_head(rel, ext, mime, head))

            # Layer 5: malicious PDF active-content markers from head_hex bytes.
            # Supports optional "pdf_sample_hex" for a larger PDF sample window.
            if ext == ".pdf" or mime == "application/pdf":
                raw_hex = entry.get("pdf_sample_hex") or entry.get("head_hex") or ""
                try:
                    pdf_head = bytes.fromhex(raw_hex)
                except ValueError:
                    pdf_head = b""
                findings.extend(self._layer_pdf_from_head(rel, ext, mime, pdf_head))

        logger.info("Upload manifest scan complete: %d entries, %d findings",
                    self.files_scanned, len(findings))
        return findings

    # -- Finding factory (copied verbatim from UploadScanner._mk) ---------- #
    def _mk(self, rule: Optional[Rule], rel: str, layer: str, detail: str,
            severity: Severity, mime: Optional[str], ext: str,
            fallback_cwe: str = "CWE-434", **kw) -> Finding:
        metadata = (
            resolve_rule_metadata(rule.id, rule.params)
            if rule else resolve_rule_metadata("RULE-UPLOAD-000")
        )
        return Finding(
            rule_id=rule.id if rule else "RULE-UPLOAD-000",
            module="upload_directory",
            severity=severity,
            file_path=rel,
            title=rule.name if rule else layer,
            detail=detail,
            remediation=rule.remediation if rule else "Remove the file and investigate.",
            line=None,
            cwe=rule.cwe if rule else fallback_cwe,
            owasp=rule.owasp if rule else "A05:2021",
            cvss_score=rule.cvss_score if rule else None,
            cve_references=list(rule.cve_references) if rule else [],
            **metadata,
            layer=layer,
            actual_mime=mime,
            declared_extension=ext or None,
            confidence="high",
            **kw,
        )

    # -- Layers (copied from UploadScanner; operate on rel/name/ext/mime) -- #
    def _layer_dangerous_extension(self, rel, ext, mime) -> List[Finding]:
        if ext in self.php_exts:
            return [self._mk(self.r_ext, rel, "dangerous_extension",
                             f"Executable PHP extension '{ext}' found in an upload directory.",
                             Severity.CRITICAL, mime, ext)]
        if ext in self.other_exts:
            return [self._mk(self.r_ext, rel, "dangerous_extension",
                             f"Server-side/executable extension '{ext}' found in an upload "
                             f"directory.", Severity.HIGH, mime, ext)]
        return []

    def _layer_double_extension(self, rel, name, ext, mime) -> List[Finding]:
        parts = name.lower().split(".")
        if len(parts) < 3:
            return []
        middle = ["." + p for p in parts[1:-1]]
        hidden = [m for m in middle if m in self.dangerous_exts]
        if hidden:
            return [self._mk(self.r_double, rel, "double_extension",
                             f"Filename '{name}' hides an executable extension "
                             f"({', '.join(hidden)}) before its final '.{parts[-1]}' extension.",
                             Severity.HIGH, mime, ext)]
        return []

    def _layer_mime_mismatch(self, rel, ext, mime) -> List[Finding]:
        if not mime:
            return []
        m = mime.lower()
        is_php_ext = ext in self.php_exts
        is_dangerous_ext = ext in self.dangerous_exts

        if m in self.php_mimes and not is_php_ext:
            return [self._mk(self.r_mime, rel, "mime_mismatch",
                             f"File declares '{ext or 'no'}' extension but its content is PHP "
                             f"({mime}).", Severity.CRITICAL, mime, ext)]
        if m in self.exec_mimes and not is_dangerous_ext:
            return [self._mk(self.r_mime, rel, "mime_mismatch",
                             f"File declares '{ext or 'no'}' extension but its content is a native "
                             f"executable ({mime}).", Severity.MEDIUM, mime, ext)]
        expected = self.expected_mime.get(ext)
        if expected and not any(m.startswith(e) for e in expected):
            return [self._mk(self.r_mime, rel, "mime_mismatch",
                             f"Extension '{ext}' implies {expected} but detected content type is "
                             f"'{mime}'.", Severity.MEDIUM, mime, ext)]
        return []

    # -- Layers 4 & 5: detection from head_hex bytes (computed service-side) -- #
    def _layer_webshell_from_head(self, rel, ext, mime, head: bytes) -> List[Finding]:
        """Match compiled webshell signature patterns against the head bytes."""
        text = head.decode("utf-8", "replace")
        matches = []
        for _sig_id, pattern, detail in self.signatures:
            if pattern.search(text):
                matches.append(detail or _sig_id)
        if not matches:
            return []
        shown = matches[:5]
        more = f" (+{len(matches) - 5} more)" if len(matches) > 5 else ""
        return [self._mk(self.r_shell, rel, "webshell_signature",
                         f"PHP webshell signature(s) detected: {'; '.join(shown)}{more}.",
                         Severity.CRITICAL, mime, ext, fallback_cwe="CWE-94")]

    def _layer_pdf_from_head(self, rel, ext, mime, head: bytes) -> List[Finding]:
        """Scan head bytes for PDF active-content keyword tokens."""
        found = []
        for token, detail in self.pdf_keywords:
            if token.encode("latin-1", "ignore") in head:
                found.append(detail or token)
        if not found:
            return []
        return [self._mk(self.r_pdf, rel, "pdf_payload",
                         f"PDF contains active-content markers: {'; '.join(found)}.",
                         Severity.HIGH, mime, ".pdf", fallback_cwe="CWE-434")]

