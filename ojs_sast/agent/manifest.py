"""Upload manifest builder (agent side).

Reads the OJS upload directories on the local node and produces a JSON manifest
describing each file by metadata, hash, magic-byte derived MIME, and
signature/marker evidence — without transmitting the files themselves. The
manifest is later analysed by
:class:`~ojs_sast.detectors.upload_manifest_scanner.UploadManifestScanner` on the
service.

The webshell signatures, PDF markers and extension lists are loaded from the
same ruleset (RULE-UPLOAD-001..005) the scanner uses, so a single definition
source drives both the agent and the service.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..detectors.upload_manifest_scanner import load_upload_layer_params
from ..detectors.upload_scanner import detect_mime as _magic_detect_mime
from ..ruleset.loader import Ruleset, load_ruleset

logger = logging.getLogger("ojs_sast.agent.manifest")

_HEAD_HEX_BYTES = 512


def _detect_mime_via_file(path: Path) -> Optional[str]:
    """Fallback MIME detection via the system ``file`` command."""
    try:
        proc = subprocess.run(
            ["file", "--mime-type", "-b", str(path)],
            capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env dependent
        return None
    out = proc.stdout.decode("utf-8", "replace").strip()
    return out or None


def _sniff_magic_bytes(head: bytes) -> Optional[str]:
    """Last-resort MIME guess from a handful of common magic-byte signatures."""
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    stripped = head.lstrip()
    if stripped.startswith(b"<?php") or stripped.startswith(b"<?="):
        return "text/x-php"
    return None


def detect_mime_fallback(head: bytes, path: Path) -> Optional[str]:
    """Detect MIME with a never-hard-fail fallback chain.

    python-magic → ``file --mime-type`` → simple magic-byte sniff → ``None``.
    """
    mime = _magic_detect_mime(head)
    if mime:
        return mime.lower()
    mime = _detect_mime_via_file(path)
    if mime:
        return mime.lower()
    mime = _sniff_magic_bytes(head)
    if mime:
        return mime
    return None


class UploadManifestBuilder:
    """Build upload-directory manifests from local files."""

    def __init__(self, ruleset: Optional[Ruleset] = None):
        self.params = load_upload_layer_params(ruleset or load_ruleset())

    # ----------------------------------------------------------------- #
    def build(self, upload_dirs: Sequence[Path]) -> Dict[str, Any]:
        entries: List[Dict[str, Any]] = []
        total_size = 0
        roots: List[str] = []
        seen: set = set()
        for raw in upload_dirs:
            directory = Path(raw)
            try:
                resolved = directory.resolve()
            except OSError:  # pragma: no cover
                continue
            if not directory.is_dir() or resolved in seen:
                continue
            seen.add(resolved)
            roots.append(str(directory))
            for path in sorted(directory.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    rel = str(path.relative_to(directory))
                except ValueError:  # pragma: no cover
                    rel = str(path)
                entry = self._build_entry(path, rel)
                entries.append(entry)
                total_size += int(entry.get("size", 0) or 0)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "upload_roots": roots,
            "total_files": len(entries),
            "total_size_bytes": total_size,
            "entries": entries,
        }

    # ----------------------------------------------------------------- #
    def _build_entry(self, path: Path, rel: str) -> Dict[str, Any]:
        name = path.name
        ext = path.suffix.lower()
        try:
            stat = path.stat()
            with path.open("rb") as fh:
                head = fh.read(self.params.shell_max)
        except OSError as exc:  # pragma: no cover
            logger.warning("Cannot read upload file %s: %s", path, exc)
            return {"path": rel, "filename": name, "extension": ext, "error": str(exc)}

        mime = detect_mime_fallback(head, path)

        parts = name.lower().split(".")
        hidden_exec: Optional[str] = None
        if len(parts) >= 3:
            for middle in parts[1:-1]:
                cand = "." + middle
                if cand in self.params.dangerous_exts:
                    hidden_exec = cand
                    break

        webshell_matches = self._match_signatures(head)
        pdf_markers: List[str] = []
        if ext == ".pdf" or mime == "application/pdf":
            pdf_markers = self._scan_pdf(path)

        stripped = head.lstrip()
        php_pattern = stripped.startswith(b"<?php") or stripped.startswith(b"<?=") \
            or b"<?php" in head

        return {
            "path": rel,
            "filename": name,
            "extension": ext,
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "sha256": self._sha256(path),
            "head_hex": head[:_HEAD_HEX_BYTES].hex(),
            "detected_mime": mime,
            "double_extension": hidden_exec is not None,
            "hidden_executable_extension": hidden_exec,
            "null_byte_in_name": "\x00" in name,
            "is_hidden": name.startswith("."),
            "php_pattern_found": bool(php_pattern),
            "webshell_signature_matches": webshell_matches,
            "pdf_active_markers": pdf_markers,
        }

    # ----------------------------------------------------------------- #
    def _match_signatures(self, head: bytes) -> List[str]:
        """Run the webshell signatures over the file head (mirrors UploadScanner)."""
        text = head.decode("utf-8", "replace")
        matched: List[str] = []
        for sig_id, pattern, detail in self.params.signatures:
            if pattern.search(text):
                matched.append(detail or sig_id)
        return matched

    def _scan_pdf(self, path: Path) -> List[str]:
        try:
            with path.open("rb") as fh:
                data = fh.read(self.params.pdf_max)
        except OSError:  # pragma: no cover
            return []
        found: List[str] = []
        for token, detail in self.params.pdf_keywords:
            if token.encode("latin-1", "ignore") in data:
                found.append(detail or token)
        return found

    @staticmethod
    def _sha256(path: Path) -> Optional[str]:
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
        except OSError:  # pragma: no cover
            return None
        return h.hexdigest()
