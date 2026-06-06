"""Tests for the service-side upload manifest scanner.

All tests use raw-evidence manifest entries (head_hex, extension, mime) —
the scanner performs its own webshell/PDF matching service-side.
"""

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


def test_upload_manifest_scanner_detects_double_extension_from_filename(ruleset):
    """Layer 2 must detect hidden executable extension from the filename alone."""
    scanner = UploadManifestScanner(ruleset)
    entry = {
        "path": "journals/1/articles/55/shell.php.jpg",
        "filename": "shell.php.jpg",
        "extension": ".jpg",
        "detected_mime": "image/jpeg",
        "head_hex": "",
    }
    findings = scanner.scan([entry])
    de = [f for f in findings if f.layer == "double_extension"]
    assert de
    assert de[0].severity == Severity.HIGH
    assert ".php" in de[0].detail


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


def test_upload_manifest_scanner_detects_webshell_from_head_hex(ruleset):
    """Layer 4 must detect webshell signatures from head_hex bytes."""
    # Craft a PHP webshell-like head that contains eval(base64_decode(
    php_code = b"<?php eval(base64_decode('dGVzdA=='));"
    scanner = UploadManifestScanner(ruleset)
    entry = {
        "path": "uploads/shell.jpg",
        "filename": "shell.jpg",
        "extension": ".jpg",
        "detected_mime": "text/x-php",  # MIME mismatch opens the webshell gate
        "head_hex": php_code.hex(),
    }
    findings = scanner.scan([entry])
    ws = [f for f in findings if f.layer == "webshell_signature"]
    assert ws, "expected webshell_signature finding from head_hex"
    assert ws[0].severity == Severity.CRITICAL


def test_upload_manifest_scanner_detects_pdf_marker_from_head_hex(ruleset):
    """Layer 5 must detect malicious PDF markers from head_hex bytes."""
    # Craft a PDF head containing a /JavaScript marker.
    pdf_head = b"%PDF-1.4\n1 0 obj\n<</Type /Catalog /OpenAction <</S /JavaScript /JS (app.alert('x'))>>>>\nendobj"
    scanner = UploadManifestScanner(ruleset)
    entry = {
        "path": "docs/evil.pdf",
        "filename": "evil.pdf",
        "extension": ".pdf",
        "detected_mime": "application/pdf",
        "head_hex": pdf_head.hex(),
    }
    findings = scanner.scan([entry])
    pdf = [f for f in findings if f.layer == "pdf_payload"]
    assert pdf, "expected pdf_payload finding from head_hex"
    assert pdf[0].severity == Severity.HIGH
    assert "JavaScript" in pdf[0].detail or "JS" in pdf[0].detail


def test_upload_manifest_scanner_does_not_require_agent_precomputed_matches(ruleset):
    """The scanner must NOT depend on 'webshell_signature_matches' or 'pdf_active_markers'.

    Even when those fields are absent, the scanner should still detect issues
    from head_hex alone.
    """
    php_code = b"<?php system($_GET['cmd']);"
    scanner = UploadManifestScanner(ruleset)
    # Entry with NO agent-precomputed fields — only raw evidence.
    entry = {
        "path": "uploads/backdoor.txt",
        "filename": "backdoor.txt",
        "extension": ".txt",
        "detected_mime": "text/plain",
        "head_hex": php_code.hex(),
        # Deliberately NO webshell_signature_matches or pdf_active_markers.
    }
    findings = scanner.scan([entry])
    ws = [f for f in findings if f.layer == "webshell_signature"]
    assert ws, "scanner should detect webshell from head_hex without precomputed matches"


def test_webshell_gate_respected_from_head_hex(ruleset):
    """Webshell layer only fires when gate is satisfied (mirrors UploadScanner)."""
    php_code = b"<?php eval(base64_decode('dGVzdA=='));"
    scanner = UploadManifestScanner(ruleset)

    # Consistent benign image (ext matches MIME) -> no mismatch -> gate false.
    benign = {"path": "a.jpg", "filename": "a.jpg", "extension": ".jpg",
              "detected_mime": "image/jpeg", "head_hex": php_code.hex()}
    assert not any(f.layer == "webshell_signature" for f in scanner.scan([benign]))

    # text/plain MIME opens the gate even for a benign .txt extension.
    gated = {"path": "a.txt", "filename": "a.txt", "extension": ".txt",
             "detected_mime": "text/plain", "head_hex": php_code.hex()}
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
