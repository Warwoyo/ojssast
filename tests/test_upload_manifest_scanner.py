"""Tests for the service-side upload manifest scanner."""

from __future__ import annotations

from ojs_sast.detectors.upload_manifest_scanner import UploadManifestScanner
from ojs_sast.detectors.upload_scanner import UploadScanner
from ojs_sast.models import Severity


def test_dangerous_php_extension(ruleset):
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "j/shell.php", "filename": "shell.php", "extension": ".php",
         "detected_mime": "text/x-php"},
    ])
    dangerous = [f for f in findings if f.layer == "dangerous_extension"]
    assert dangerous, "expected a dangerous_extension finding"
    f = dangerous[0]
    assert f.severity == Severity.CRITICAL
    assert f.module == "upload_directory"
    assert f.declared_extension == ".php"
    assert f.file_path == "j/shell.php"
    assert f.line is None


def test_double_extension(ruleset):
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "image.php.jpg", "filename": "image.php.jpg", "extension": ".jpg",
         "detected_mime": "image/jpeg"},
    ])
    de = [f for f in findings if f.layer == "double_extension"]
    assert de and de[0].severity == Severity.HIGH


def test_mime_mismatch_php_as_jpg(ruleset):
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "fake.jpg", "filename": "fake.jpg", "extension": ".jpg",
         "detected_mime": "text/x-php"},
    ])
    mm = [f for f in findings if f.layer == "mime_mismatch"]
    assert mm and mm[0].severity == Severity.CRITICAL
    assert mm[0].actual_mime == "text/x-php"
    assert mm[0].declared_extension == ".jpg"


def test_pdf_markers(ruleset):
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "a.pdf", "filename": "a.pdf", "extension": ".pdf",
         "detected_mime": "application/pdf",
         "pdf_active_markers": ["Embedded JavaScript", "Launch action"]},
    ])
    pdf = [f for f in findings if f.layer == "pdf_payload"]
    assert pdf and pdf[0].severity == Severity.HIGH
    assert "Embedded JavaScript" in pdf[0].detail


def test_webshell_gate_respected(ruleset):
    """A signature match must not fire unless the webshell gate is satisfied.

    Mirrors UploadScanner._scan_file: the webshell layer only runs when a
    dangerous extension / MIME mismatch fired, or the MIME is PHP / text/plain.
    """
    scanner = UploadManifestScanner(ruleset)
    matches = ["eval(base64_decode(...)) packed payload"]

    # Consistent benign image (ext matches MIME) -> no mismatch -> gate false.
    benign = {"path": "a.jpg", "filename": "a.jpg", "extension": ".jpg",
              "detected_mime": "image/jpeg", "webshell_signature_matches": matches}
    assert not any(f.layer == "webshell_signature" for f in scanner.scan([benign]))

    # text/plain MIME opens the gate even for a benign .txt extension.
    gated = {"path": "a.txt", "filename": "a.txt", "extension": ".txt",
             "detected_mime": "text/plain", "webshell_signature_matches": matches}
    fired = [f for f in scanner.scan([gated]) if f.layer == "webshell_signature"]
    assert fired and fired[0].severity == Severity.CRITICAL


def test_error_entry_skipped(ruleset):
    scanner = UploadManifestScanner(ruleset)
    assert scanner.scan([{"path": "x", "error": "unreadable"}]) == []


def test_param_parity_with_upload_scanner(ruleset):
    """Resolved layer params must match the local UploadScanner (drift guard)."""
    manifest = UploadManifestScanner(ruleset)
    local = UploadScanner(ruleset)
    assert manifest.php_exts == local.php_exts
    assert manifest.other_exts == local.other_exts
    assert manifest.dangerous_exts == local.dangerous_exts
    assert manifest.php_mimes == local.php_mimes
    assert manifest.exec_mimes == local.exec_mimes
    assert manifest.expected_mime == local.expected_mime
