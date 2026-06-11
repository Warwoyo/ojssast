"""``ScanBundle`` — the input model for remote / agent-push scans.

A :class:`ScanBundle` carries everything the SAST service needs to analyse an
OJS deployment *without* direct filesystem access to it:

* ``source_root`` — the directory where the agent's filtered ``source.tar.gz``
  has already been safely extracted,
* ``config_files`` — the raw configuration text payload (``config.inc.php`` and
  any nginx/apache configs the agent collected),
* ``upload_manifest`` — the list of upload-directory *manifest entries* (file
  metadata, hashes, magic-byte derived MIME and signature/marker evidence); the
  upload files themselves are never transmitted.

The bundle is normally built from an agent ``meta.json`` via :meth:`from_meta`.

This module is intentionally pure stdlib so that ``Orchestrator.run_bundle`` and
the ``ojs-sast scan-bundle`` CLI work on a bare install without the optional
``service`` / ``agent`` dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def resolve_source_root(extract_dir, meta: Dict[str, Any]) -> Optional[Path]:
    """Locate the extracted source root, honoring the archive's top-level dir.

    Prefers ``meta["source_archive"]["top_level_dir"]``; falls back to a single
    top-level subdirectory, else the extraction directory itself.
    """
    extract_dir = Path(extract_dir)
    archive_meta = meta.get("source_archive") or {}
    top = archive_meta.get("top_level_dir")
    if top:
        candidate = extract_dir / top
        if candidate.is_dir():
            return candidate
    subdirs = [p for p in extract_dir.iterdir() if p.is_dir()] if extract_dir.is_dir() else []
    if len(subdirs) == 1:
        return subdirs[0]
    return extract_dir


@dataclass
class ScanBundle:
    """A normalized, transport-agnostic description of a remote scan target."""

    source_root: Optional[Path]
    config_files: Dict[str, str] = field(default_factory=dict)
    # List of upload manifest entries (dicts). ``None`` means "no upload module".
    upload_manifest: Optional[List[Dict[str, Any]]] = None

    # Target facts computed by the agent (on the full install) and shipped verbatim.
    ojs_version: Optional[str] = None
    ojs_detected: bool = False
    detection_markers: List[str] = field(default_factory=list)

    # Provenance / audit (never secrets).
    agent_id: Optional[str] = None
    agent_version: Optional[str] = None
    agent_hostname: Optional[str] = None
    bundle_id: Optional[str] = None
    source_label: Optional[str] = None
    source_archive_sha256: Optional[str] = None
    source_archive_bytes: Optional[int] = None
    created_at: Optional[str] = None

    @classmethod
    def from_meta(cls, meta: Dict[str, Any], source_root: Optional[Path]) -> "ScanBundle":
        """Build a bundle from a parsed ``meta.json`` and an extracted source dir.

        ``source_root`` is the directory the archive was extracted into (the
        caller is responsible for safe extraction). ``upload_manifest`` accepts
        either the richer object form ``{"entries": [...], ...}`` or a plain list
        of entries.
        """
        raw_manifest = meta.get("upload_manifest")
        if isinstance(raw_manifest, dict):
            entries: Optional[List[Dict[str, Any]]] = list(raw_manifest.get("entries") or [])
        elif isinstance(raw_manifest, list):
            entries = list(raw_manifest)
        else:
            entries = None

        source_archive = meta.get("source_archive") or {}
        return cls(
            source_root=Path(source_root) if source_root is not None else None,
            config_files=dict(meta.get("config_files") or {}),
            upload_manifest=entries,
            ojs_version=meta.get("ojs_version"),
            ojs_detected=bool(meta.get("ojs_detected", False)),
            detection_markers=list(meta.get("detection_markers") or []),
            agent_id=meta.get("agent_id"),
            agent_version=meta.get("agent_version"),
            agent_hostname=meta.get("agent_hostname"),
            bundle_id=meta.get("bundle_id"),
            source_label=meta.get("source_label"),
            source_archive_sha256=source_archive.get("sha256"),
            source_archive_bytes=source_archive.get("bytes"),
            created_at=meta.get("created_at"),
        )
