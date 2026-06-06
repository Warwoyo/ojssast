"""Source snapshot builder (agent side).

Builds a filtered ``source.tar.gz`` of the OJS install: only relevant source
extensions are included, and upload directories, VCS metadata, caches,
``node_modules``/``vendor`` and binary/oversized files are excluded. The upload
directory is deliberately *not* shipped (only its manifest is — see
:mod:`ojs_sast.agent.manifest`).
"""

from __future__ import annotations

import hashlib
import logging
import tarfile
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple

logger = logging.getLogger("ojs_sast.agent.snapshot")

INCLUDE_EXTENSIONS = {
    ".php", ".inc", ".tpl", ".smarty", ".js", ".json", ".xml", ".yml", ".yaml",
}

EXCLUDE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "bower_components", "vendor",
    "cache", "tmp", "logs",
    "files", "uploads",
    "__pycache__", ".idea", ".vscode",
}

# Files always included even if their extension is not in INCLUDE_EXTENSIONS
# (so the service can still detect the OJS version as a fallback).
WHITELIST_FILES = {"version.xml"}

MAX_SOURCE_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_source_archive(
    ojs_root,
    out_path,
    *,
    exclude_paths: Optional[Iterable[Path]] = None,
    max_file_size: int = MAX_SOURCE_FILE_SIZE,
    top_level_dir: str = "source",
) -> Tuple[str, int]:
    """Write a filtered ``tar.gz`` of ``ojs_root`` to ``out_path``.

    ``exclude_paths`` is an iterable of directories (e.g. resolved upload dirs)
    whose contents must not be shipped. Returns ``(sha256, size_bytes)`` of the
    produced archive.
    """
    ojs_root = Path(ojs_root).resolve()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    exclude_resolved: Set[Path] = set()
    for p in (exclude_paths or []):
        try:
            exclude_resolved.add(Path(p).resolve())
        except OSError:  # pragma: no cover
            continue

    included = 0
    with tarfile.open(out_path, "w:gz") as tar:
        for path in sorted(ojs_root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(ojs_root)
            if any(part in EXCLUDE_DIRS for part in rel.parts):
                continue
            try:
                rp = path.resolve()
            except OSError:  # pragma: no cover
                continue
            if any(_is_within(ex, rp) for ex in exclude_resolved):
                continue
            name = path.name
            if path.suffix.lower() not in INCLUDE_EXTENSIONS and name not in WHITELIST_FILES:
                continue
            try:
                if path.stat().st_size > max_file_size:
                    continue
                with path.open("rb") as fh:
                    sniff = fh.read(4096)
            except OSError:  # pragma: no cover
                continue
            if b"\x00" in sniff:  # binary heuristic (mirrors the CVE scanner)
                continue

            arcname = f"{top_level_dir}/" + str(rel).replace("\\", "/")
            info = tar.gettarinfo(str(path), arcname=arcname)
            # Strip host identity for privacy / reproducibility.
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as fh:
                tar.addfile(info, fh)
            included += 1

    size = out_path.stat().st_size
    sha256 = _sha256_file(out_path)
    logger.info("Source snapshot: %d files, %d bytes -> %s", included, size, out_path)
    return sha256, size
