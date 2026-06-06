"""Tests for the agent-side upload manifest builder."""

from __future__ import annotations

from pathlib import Path

from ojs_sast.agent.manifest import UploadManifestBuilder

FIXTURES = Path(__file__).parent / "fixtures"


def test_build_from_malicious_fixtures(ruleset):
    manifest = UploadManifestBuilder(ruleset).build([FIXTURES / "upload" / "malicious"])
    assert manifest["total_files"] >= 1
    by_name = {e["filename"]: e for e in manifest["entries"]}

    shell = by_name["shell.php"]
    assert shell["extension"] == ".php"
    assert shell["php_pattern_found"] is True
    assert shell["webshell_signature_matches"], "shell.php should match webshell signatures"
    assert len(shell["sha256"]) == 64
    assert shell["head_hex"]  # short evidence present
    assert shell["size"] > 0

    dbl = by_name["image.php.jpg"]
    assert dbl["double_extension"] is True
    assert dbl["hidden_executable_extension"] == ".php"

    evil = by_name["evil.pdf"]
    assert evil["pdf_active_markers"], "evil.pdf should expose active-content markers"


def test_clean_fixtures_have_no_evidence(ruleset):
    manifest = UploadManifestBuilder(ruleset).build([FIXTURES / "upload" / "clean"])
    assert manifest["entries"]
    for entry in manifest["entries"]:
        assert not entry.get("webshell_signature_matches")
        assert not entry.get("pdf_active_markers")


def test_no_raw_content_beyond_head(ruleset):
    """The manifest must not embed full file contents — only a 512-byte head hex."""
    manifest = UploadManifestBuilder(ruleset).build([FIXTURES / "upload" / "malicious"])
    for entry in manifest["entries"]:
        # 512 bytes -> at most 1024 hex chars.
        assert len(entry.get("head_hex", "")) <= 1024
