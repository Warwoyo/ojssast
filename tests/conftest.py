"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
import warnings
from pathlib import Path

import pytest

warnings.simplefilter("ignore")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def ruleset():
    from ojs_sast.ruleset.loader import load_ruleset

    return load_ruleset()


@pytest.fixture
def mock_ojs(tmp_path):
    """Build a minimal but realistic OJS install tree under tmp_path."""
    root = tmp_path / "ojs"
    (root / "lib" / "pkp" / "classes" / "core").mkdir(parents=True)
    (root / "classes" / "core").mkdir(parents=True)
    (root / "dbscripts" / "xml").mkdir(parents=True)
    (root / "pages" / "issue").mkdir(parents=True)

    (root / "classes" / "core" / "PKPApplication.php").write_text(
        "<?php\nclass PKPApplication {}\n", encoding="utf-8")
    (root / "dbscripts" / "xml" / "version.xml").write_text(
        "<version><application>ojs2</application><release>3.3.0-13</release></version>",
        encoding="utf-8")

    # Insecure config so config module produces findings.
    shutil.copy(FIXTURES / "config" / "insecure_config.inc.php", root / "config.inc.php")

    # A vulnerable source file inside the install.
    shutil.copy(FIXTURES / "vulnerable_php" / "xss_sample.php",
                root / "pages" / "issue" / "IssueHandler.inc.php")
    shutil.copy(FIXTURES / "vulnerable_php" / "sqli_sample.php",
                root / "classes" / "core" / "SubmissionSearchDAO.inc.php")

    # files_dir = "files" (relative -> inside webroot) holds a webshell.
    files_dir = root / "files"
    files_dir.mkdir()
    shutil.copy(FIXTURES / "upload" / "malicious" / "shell.php", files_dir / "shell.php")
    shutil.copy(FIXTURES / "upload" / "malicious" / "fake_image.jpg", files_dir / "fake_image.jpg")

    return root
