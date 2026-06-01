"""Upload-directory scanner.

Walks the resolved OJS upload directories and applies five detection layers:

1. Dangerous file extension
2. Double-extension masquerade
3. MIME type vs. extension mismatch (python-magic)
4. PHP webshell signature scan
5. Malicious-PDF marker scan

Findings carry ``layer``, ``actual_mime`` and ``declared_extension`` metadata.
If python-magic is unavailable the MIME-dependent layers degrade gracefully.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from ..models import Finding, Rule, Severity
from ..ruleset.loader import Ruleset

logger = logging.getLogger("ojs_sast.upload")

MAGIC_AVAILABLE = False
_magic_instance = None
try:  # pragma: no cover - import guard
    import magic as _magic_mod

    _magic_instance = _magic_mod.Magic(mime=True)
    MAGIC_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    logger.warning("python-magic unavailable; MIME layers degraded: %s", exc)


def detect_mime(data: bytes) -> Optional[str]:
    if not MAGIC_AVAILABLE or _magic_instance is None:
        return None
    try:
        return _magic_instance.from_buffer(data)
    except Exception as exc:  # pragma: no cover
        logger.debug("magic failed: %s", exc)
        return None


class UploadScanner:
    def __init__(self, ruleset: Ruleset, ojs_path: Optional[Path] = None,
                 verbose: bool = False,
                 progress_cb: Optional[Callable[[str], None]] = None):
        self.ruleset = ruleset
        self.ojs_path = Path(ojs_path).resolve() if ojs_path else None
        self.verbose = verbose
        self.progress_cb = progress_cb
        self.files_scanned = 0

        # Resolve rules and parameters up front.
        self.r_ext = ruleset.get("RULE-UPLOAD-001")
        self.r_double = ruleset.get("RULE-UPLOAD-002")
        self.r_mime = ruleset.get("RULE-UPLOAD-003")
        self.r_shell = ruleset.get("RULE-UPLOAD-004")
        self.r_pdf = ruleset.get("RULE-UPLOAD-005")

        p = self.r_ext.params if self.r_ext else {}
        self.php_exts = {e.lower() for e in p.get("php_extensions", [])}
        self.other_exts = {
            e.lower() for e in (
                p.get("server_extensions", []) + p.get("executable_extensions", [])
                + p.get("java_extensions", [])
            )
        }
        self.dangerous_exts = self.php_exts | self.other_exts

        mp = self.r_mime.params if self.r_mime else {}
        self.php_mimes = {m.lower() for m in mp.get("php_mimes", [])}
        self.exec_mimes = {m.lower() for m in mp.get("executable_mimes", [])}
        self.expected_mime = {k.lower(): [v.lower() for v in vs]
                              for k, vs in (mp.get("expected_mime", {}) or {}).items()}

        sp = self.r_shell.params if self.r_shell else {}
        self.shell_max = int(sp.get("max_bytes", 65536))
        flags = re.IGNORECASE if sp.get("case_insensitive", True) else 0
        self.signatures = []
        for sig in sp.get("signatures", []):
            try:
                self.signatures.append((sig.get("id", "?"),
                                        re.compile(sig["pattern"], flags),
                                        sig.get("detail", "")))
            except re.error as exc:  # pragma: no cover
                logger.error("Bad webshell signature %s: %s", sig.get("id"), exc)

        pp = self.r_pdf.params if self.r_pdf else {}
        self.pdf_max = int(pp.get("max_bytes", 1048576))
        self.pdf_keywords = [(k["token"], k.get("detail", "")) for k in pp.get("keywords", [])]

    # ----------------------------------------------------------------- #
    def _progress(self, msg: str) -> None:
        if self.progress_cb:
            self.progress_cb(msg)

    def _is_safe_target(self, directory: Path) -> bool:
        """Refuse to scan the OJS root itself (would scan the whole codebase)."""
        try:
            d = directory.resolve()
        except OSError:  # pragma: no cover
            return False
        if not d.is_dir():
            logger.warning("Upload dir does not exist or is not a directory: %s", directory)
            return False
        if self.ojs_path is not None:
            if d == self.ojs_path or d in self.ojs_path.parents:
                logger.error(
                    "Refusing to scan upload dir %s: it is the OJS root or an ancestor of it.", d)
                return False
        return True

    def scan(self, upload_dirs: Sequence[Path]) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()
        for raw in upload_dirs:
            directory = Path(raw)
            if not self._is_safe_target(directory):
                continue
            resolved = directory.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            for path in sorted(directory.rglob("*")):
                if not path.is_file():
                    continue
                rel = str(path.relative_to(directory))
                self.files_scanned += 1
                if self.verbose:
                    self._progress(f"upload: {rel}")
                findings.extend(self._scan_file(path, rel))
        logger.info("Upload scan complete: %d files, %d findings", self.files_scanned, len(findings))
        return findings

    # ----------------------------------------------------------------- #
    def _scan_file(self, path: Path, rel: str) -> List[Finding]:
        findings: List[Finding] = []
        name = path.name
        ext = path.suffix.lower()

        try:
            with path.open("rb") as fh:
                head = fh.read(self.shell_max)
        except OSError as exc:  # pragma: no cover
            logger.warning("Cannot read %s: %s", path, exc)
            return findings

        mime = detect_mime(head)

        # Layer 1: dangerous extension
        l1 = self._layer_dangerous_extension(rel, ext, mime)
        findings.extend(l1)

        # Layer 2: double extension
        findings.extend(self._layer_double_extension(rel, name, ext, mime))

        # Layer 3: MIME mismatch
        l3 = self._layer_mime_mismatch(rel, ext, mime)
        findings.extend(l3)

        # Layer 4: webshell signatures (gated)
        gate = bool(l1) or bool(l3) or (mime in self.php_mimes) or (mime in ("text/plain",))
        if gate and self.signatures:
            findings.extend(self._layer_webshell(rel, ext, mime, head))

        # Layer 5: malicious PDF
        if ext == ".pdf" or mime == "application/pdf":
            findings.extend(self._layer_pdf(path, rel, mime))

        return findings

    def _mk(self, rule: Optional[Rule], rel: str, layer: str, detail: str,
            severity: Severity, mime: Optional[str], ext: str,
            fallback_cwe: str = "CWE-434", **kw) -> Finding:
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
            layer=layer,
            actual_mime=mime,
            declared_extension=ext or None,
            confidence="high",
            **kw,
        )

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

    def _layer_webshell(self, rel, ext, mime, head: bytes) -> List[Finding]:
        text = head.decode("utf-8", "replace")
        matched = []
        for sig_id, pattern, detail in self.signatures:
            if pattern.search(text):
                matched.append(detail or sig_id)
        if not matched:
            return []
        shown = matched[:5]
        more = f" (+{len(matched) - 5} more)" if len(matched) > 5 else ""
        return [self._mk(self.r_shell, rel, "webshell_signature",
                         f"PHP webshell signature(s) detected: {'; '.join(shown)}{more}.",
                         Severity.CRITICAL, mime, ext, fallback_cwe="CWE-94")]

    def _layer_pdf(self, path: Path, rel, mime) -> List[Finding]:
        try:
            with path.open("rb") as fh:
                data = fh.read(self.pdf_max)
        except OSError:  # pragma: no cover
            return []
        found = []
        for token, detail in self.pdf_keywords:
            if token.encode("latin-1", "ignore") in data:
                found.append(detail or token)
        if not found:
            return []
        return [self._mk(self.r_pdf, rel, "pdf_payload",
                         f"PDF contains active-content markers: {'; '.join(found)}.",
                         Severity.HIGH, mime, ".pdf", fallback_cwe="CWE-434")]
