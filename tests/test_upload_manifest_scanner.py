"""Tests for the service-side upload manifest scanner."""

from __future__ import annotations

from ojs_sast.detectors.upload_manifest_scanner import UploadManifestScanner
from ojs_sast.detectors.upload_scanner import UploadScanner
from ojs_sast.models import Severity

# Hex-encoded head bytes for webshell/PDF tests.
_WEBSHELL_HEX = "<?php eval(base64_decode('dGVzdA=='));".encode().hex()
_WEBSHELL_SYSTEM_HEX = "<?php system($_GET['c']);".encode().hex()
_PDF_HEX = "%PDF-1.4\n/JavaScript (alert(1))\n/OpenAction <<>>\n".encode().hex()
_BENIGN_HEX = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00".hex()


def test_dangerous_php_extension(ruleset):
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "j/shell.php", "filename": "shell.php", "extension": ".php",
         "detected_mime": "text/x-php", "head_hex": _WEBSHELL_HEX},
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
         "detected_mime": "image/jpeg", "head_hex": _BENIGN_HEX},
    ])
    de = [f for f in findings if f.layer == "double_extension"]
    assert de and de[0].severity == Severity.HIGH


def test_upload_manifest_scanner_detects_double_extension_from_filename(ruleset):
    """Double extension is detected from filename alone (no head_hex needed)."""
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "uploads/doc.php.txt", "filename": "doc.php.txt",
         "extension": ".txt", "detected_mime": "text/plain"},
    ])
    de = [f for f in findings if f.layer == "double_extension"]
    assert de, "expected double_extension finding"
    assert de[0].severity == Severity.HIGH
    assert ".php" in de[0].detail


def test_mime_mismatch_php_as_jpg(ruleset):
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "fake.jpg", "filename": "fake.jpg", "extension": ".jpg",
         "detected_mime": "text/x-php", "head_hex": _WEBSHELL_HEX},
    ])
    mm = [f for f in findings if f.layer == "mime_mismatch"]
    assert mm and mm[0].severity == Severity.CRITICAL
    assert mm[0].actual_mime == "text/x-php"
    assert mm[0].declared_extension == ".jpg"


def test_upload_manifest_scanner_detects_webshell_from_head_hex(ruleset):
    """Webshell is detected from head_hex bytes — no pre-computed agent field needed."""
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "uploads/shell.php", "filename": "shell.php", "extension": ".php",
         "detected_mime": "text/x-php", "head_hex": _WEBSHELL_HEX},
    ])
    ws = [f for f in findings if f.layer == "webshell_signature"]
    assert ws, "expected webshell_signature finding from head_hex"
    assert ws[0].severity == Severity.CRITICAL
    assert "eval(base64_decode" in ws[0].detail


def test_upload_manifest_scanner_detects_pdf_marker_from_head_hex(ruleset):
    """PDF active-content markers are detected from head_hex bytes."""
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "submission.pdf", "filename": "submission.pdf", "extension": ".pdf",
         "detected_mime": "application/pdf", "head_hex": _PDF_HEX},
    ])
    pdf = [f for f in findings if f.layer == "pdf_payload"]
    assert pdf, "expected pdf_payload finding from head_hex"
    assert pdf[0].severity == Severity.HIGH
    assert "JavaScript" in pdf[0].detail


def test_upload_manifest_scanner_does_not_require_agent_precomputed_matches(ruleset):
    """Scanner computes webshell/PDF matches itself; pre-computed fields are ignored."""
    scanner = UploadManifestScanner(ruleset)
    # Entry has old agent fields but NO head_hex — scanner must not use old fields.
    findings = scanner.scan([
        {"path": "a.pdf", "filename": "a.pdf", "extension": ".pdf",
         "detected_mime": "application/pdf",
         "pdf_active_markers": ["Embedded JavaScript"],  # old agent field — ignored
         "webshell_signature_matches": ["eval(...)"],   # old agent field — ignored
         "head_hex": ""},  # empty head → no detection
    ])
    assert not any(f.layer in ("pdf_payload", "webshell_signature") for f in findings), (
        "pre-computed agent fields must not trigger findings; only head_hex is used"
    )


def test_webshell_gate_respected(ruleset):
    """Webshell layer only fires when the gate condition is satisfied.

    Gate is true when: dangerous extension fired, MIME mismatch fired, MIME is
    PHP/text-plain. Gate is false for a consistent benign image.
    """
    scanner = UploadManifestScanner(ruleset)

    # Consistent benign image (ext matches MIME) → gate false → no webshell.
    benign = {"path": "a.jpg", "filename": "a.jpg", "extension": ".jpg",
              "detected_mime": "image/jpeg", "head_hex": _WEBSHELL_HEX}
    assert not any(f.layer == "webshell_signature" for f in scanner.scan([benign]))

    # text/plain MIME opens the gate even for a benign .txt extension.
    gated = {"path": "a.txt", "filename": "a.txt", "extension": ".txt",
             "detected_mime": "text/plain", "head_hex": _WEBSHELL_SYSTEM_HEX}
    fired = [f for f in scanner.scan([gated]) if f.layer == "webshell_signature"]
    assert fired and fired[0].severity == Severity.CRITICAL


def test_pdf_markers_from_head_hex(ruleset):
    """PDF markers are detected from head_hex bytes."""
    scanner = UploadManifestScanner(ruleset)
    findings = scanner.scan([
        {"path": "a.pdf", "filename": "a.pdf", "extension": ".pdf",
         "detected_mime": "application/pdf", "head_hex": _PDF_HEX},
    ])
    pdf = [f for f in findings if f.layer == "pdf_payload"]
    assert pdf and pdf[0].severity == Severity.HIGH
    assert "JavaScript" in pdf[0].detail


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
