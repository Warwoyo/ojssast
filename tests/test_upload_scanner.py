"""Tests for the upload directory scanner (5 detection layers)."""

from ojs_sast.detectors.upload_scanner import MAGIC_AVAILABLE, UploadScanner

from .conftest import FIXTURES


def _layers(findings):
    return {f.layer for f in findings}


def _for_file(findings, name):
    return [f for f in findings if f.file_path.endswith(name)]


def test_clean_directory_no_findings(ruleset):
    sc = UploadScanner(ruleset)
    assert sc.scan([FIXTURES / "upload" / "clean"]) == []


def test_malicious_directory_layers(ruleset):
    sc = UploadScanner(ruleset)
    findings = sc.scan([FIXTURES / "upload" / "malicious"])
    layers = _layers(findings)
    assert "dangerous_extension" in layers
    assert "double_extension" in layers
    assert "webshell_signature" in layers
    assert "pdf_payload" in layers
    if MAGIC_AVAILABLE:
        assert "mime_mismatch" in layers


def test_php_extension_is_critical(ruleset):
    sc = UploadScanner(ruleset)
    findings = _for_file(sc.scan([FIXTURES / "upload" / "malicious"]), "shell.php")
    ext_findings = [f for f in findings if f.layer == "dangerous_extension"]
    assert ext_findings and ext_findings[0].severity.value == "CRITICAL"


def test_double_extension_detected(ruleset):
    sc = UploadScanner(ruleset)
    findings = _for_file(sc.scan([FIXTURES / "upload" / "malicious"]), "image.php.jpg")
    assert any(f.layer == "double_extension" and f.severity.value == "HIGH" for f in findings)


def test_webshell_signature_detected(ruleset):
    sc = UploadScanner(ruleset)
    findings = _for_file(sc.scan([FIXTURES / "upload" / "malicious"]), "shell.php")
    shell = [f for f in findings if f.layer == "webshell_signature"]
    assert shell and shell[0].severity.value == "CRITICAL"


def test_pdf_payload_detected(ruleset):
    sc = UploadScanner(ruleset)
    findings = _for_file(sc.scan([FIXTURES / "upload" / "malicious"]), "evil.pdf")
    pdf = [f for f in findings if f.layer == "pdf_payload"]
    assert pdf and pdf[0].severity.value == "HIGH"


def test_clean_pdf_not_flagged(ruleset):
    sc = UploadScanner(ruleset)
    findings = _for_file(sc.scan([FIXTURES / "upload" / "clean"]), "clean.pdf")
    assert findings == []


def test_mime_mismatch_php_as_jpg(ruleset):
    if not MAGIC_AVAILABLE:
        return
    sc = UploadScanner(ruleset)
    findings = _for_file(sc.scan([FIXTURES / "upload" / "malicious"]), "fake_image.jpg")
    mm = [f for f in findings if f.layer == "mime_mismatch"]
    assert mm and mm[0].severity.value == "CRITICAL"
    assert mm[0].declared_extension == ".jpg"
    assert "php" in (mm[0].actual_mime or "")


def test_refuses_to_scan_ojs_root(ruleset, tmp_path):
    (tmp_path / "config.inc.php").write_text("x")
    sc = UploadScanner(ruleset, ojs_path=tmp_path)
    # Scanning the OJS root itself must be refused.
    assert sc.scan([tmp_path]) == []


def test_findings_have_upload_metadata(ruleset):
    sc = UploadScanner(ruleset)
    findings = sc.scan([FIXTURES / "upload" / "malicious"])
    for f in findings:
        assert f.module == "upload_directory"
        assert f.layer is not None
        assert f.line is None
