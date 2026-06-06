"""Tests for the sandboxed archive extraction (pure stdlib)."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from ojs_sast.service.extract import UnsafeArchiveError, safe_extract_archive


def _make_tar(path: Path, members) -> Path:
    """members: list of (name, data) for files, or a prepared TarInfo + data."""
    with tarfile.open(path, "w:gz") as tar:
        for member in members:
            if isinstance(member, tuple):
                name, data = member
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info, data = member.info, member.data
                tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


class _Member:
    def __init__(self, info, data=None):
        self.info = info
        self.data = data


def test_benign_archive_extracts(tmp_path):
    tar = _make_tar(tmp_path / "ok.tar.gz", [
        ("source/a.php", b"<?php echo 1;"),
        ("source/sub/b.txt", b"hello"),
    ])
    dest = tmp_path / "out"
    safe_extract_archive(tar, dest)
    assert (dest / "source" / "a.php").read_bytes() == b"<?php echo 1;"
    assert (dest / "source" / "sub" / "b.txt").read_text() == "hello"


def test_rejects_parent_traversal(tmp_path):
    tar = _make_tar(tmp_path / "evil.tar.gz", [("../escape.txt", b"x")])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_rejects_absolute_path(tmp_path):
    tar = _make_tar(tmp_path / "evil.tar.gz", [("/etc/whatever", b"x")])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out")


def test_rejects_symlink(tmp_path):
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    tar = _make_tar(tmp_path / "evil.tar.gz", [_Member(info)])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out")


def test_rejects_hardlink(tmp_path):
    info = tarfile.TarInfo("hard")
    info.type = tarfile.LNKTYPE
    info.linkname = "source/a.php"
    tar = _make_tar(tmp_path / "evil.tar.gz", [_Member(info)])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out")


def test_rejects_oversized_file(tmp_path):
    tar = _make_tar(tmp_path / "big.tar.gz", [("source/big.php", b"A" * 100)])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out", max_file_bytes=10)


def test_rejects_total_over_limit(tmp_path):
    tar = _make_tar(tmp_path / "big.tar.gz", [
        ("source/a.php", b"A" * 80),
        ("source/b.php", b"B" * 80),
    ])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out", max_total_bytes=100)


def test_rejects_too_many_files(tmp_path):
    tar = _make_tar(tmp_path / "many.tar.gz", [
        ("source/a", b"a"), ("source/b", b"b"), ("source/c", b"c"),
    ])
    with pytest.raises(UnsafeArchiveError):
        safe_extract_archive(tar, tmp_path / "out", max_files=2)
