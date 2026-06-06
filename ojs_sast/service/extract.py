"""Safe extraction of agent source archives.

Pure stdlib so it can be imported by ``Orchestrator.run_bundle`` callers (the
``ojs-sast scan-bundle`` CLI and the service worker) without the optional
``service`` dependencies.

Defends against the classic tar attacks: absolute paths, ``..`` traversal,
symlink / hardlink escapes, device / FIFO members, oversized individual files,
oversized total extraction, and archive bombs (too many members). Members are
validated up front and then extracted one by one to validated destinations
(never a blanket ``extractall``).
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

DEFAULT_MAX_FILES = 50_000
DEFAULT_MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024    # 50 MB


class UnsafeArchiveError(Exception):
    """Raised when an archive member violates the extraction safety policy."""


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def safe_extract_archive(
    tar_path,
    dest_dir,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> Path:
    """Safely extract ``tar_path`` into ``dest_dir``.

    Returns the destination directory. Raises :class:`UnsafeArchiveError` on any
    policy violation, leaving nothing extracted outside ``dest_dir``.
    """
    tar_path = Path(tar_path)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()

    total = 0
    file_count = 0
    with tarfile.open(tar_path, "r:*") as tar:
        members = tar.getmembers()
        for member in members:
            name = member.name
            if name.startswith("/") or Path(name).is_absolute():
                raise UnsafeArchiveError(f"absolute path in archive: {name!r}")
            if member.issym() or member.islnk():
                raise UnsafeArchiveError(f"link member not allowed: {name!r}")
            if not (member.isfile() or member.isdir()):
                raise UnsafeArchiveError(f"unsupported member type: {name!r}")
            target = (dest_root / name).resolve()
            if target != dest_root and not _is_within(dest_root, target):
                raise UnsafeArchiveError(f"path traversal in archive: {name!r}")
            if member.isfile():
                file_count += 1
                if file_count > max_files:
                    raise UnsafeArchiveError("archive exceeds file count limit")
                if member.size > max_file_bytes:
                    raise UnsafeArchiveError(
                        f"member too large ({member.size} bytes): {name!r}")
                total += member.size
                if total > max_total_bytes:
                    raise UnsafeArchiveError("archive exceeds total size limit")

        # All members validated — extract individually to validated destinations.
        extract_kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
        for member in members:
            tar.extract(member, path=dest_root, **extract_kwargs)
    return dest_dir
