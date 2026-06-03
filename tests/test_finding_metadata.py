from ojs_sast.models import Finding, Rule, RuleMatch, Severity, resolve_rule_metadata


def test_resolve_rule_metadata_defaults_and_param_overrides():
    assert resolve_rule_metadata("CVE-SRC-001")["ground_truth"] is True
    assert resolve_rule_metadata("CVE-SRC-001")["evaluation_scope"] == "ground_truth"
    assert resolve_rule_metadata("OJS-CFG-NGX-001")["ground_truth"] is False
    assert resolve_rule_metadata("OJS-CFG-NGX-001")["evaluation_scope"] == "extension"
    assert resolve_rule_metadata("OJS-CFG-SEC-001")["ground_truth"] is True
    assert resolve_rule_metadata("RULE-UPLOAD-001")["evaluation_scope"] == "upload"
    assert resolve_rule_metadata("RULE-SRC-001")["evaluation_scope"] == "generic"

    metadata = resolve_rule_metadata(
        "RULE-SRC-999",
        {
            "ground_truth": True,
            "evaluation_scope": "ground_truth",
            "rule_origin": "dataset",
            "rule_family": "csrf",
        },
    )
    assert metadata == {
        "ground_truth": True,
        "evaluation_scope": "ground_truth",
        "rule_origin": "dataset",
        "rule_family": "csrf",
    }


def test_finding_from_match_uses_rule_params_metadata():
    rule = Rule(
        id="RULE-SRC-999",
        name="Custom source rule",
        module="source_code",
        severity=Severity.HIGH,
        params={
            "ground_truth": True,
            "evaluation_scope": "ground_truth",
            "rule_origin": "manual",
            "rule_family": "xss",
        },
    )
    finding = Finding.from_match(RuleMatch(rule=rule, file_path="a.php", line=7, snippet="echo $x;"))

    data = finding.to_dict()
    assert data["ground_truth"] is True
    assert data["evaluation_scope"] == "ground_truth"
    assert data["rule_origin"] == "manual"
    assert data["rule_family"] == "xss"


def test_finding_to_dict_resolves_prefix_metadata_when_fields_absent():
    data = Finding(
        rule_id="OJS-CFG-SEC-001",
        module="config",
        severity=Severity.HIGH,
        file_path="config.inc.php",
    ).to_dict()

    assert data["ground_truth"] is True
    assert data["evaluation_scope"] == "ground_truth"


def test_scan_report_preserves_explicit_metadata():
    finding = Finding(
        rule_id="RULE-SRC-999",
        module="source_code",
        severity=Severity.HIGH,
        file_path="a.php",
        ground_truth=True,
        evaluation_scope="ground_truth",
        rule_origin="manual",
        rule_family="xss",
    )

    from ojs_sast.models import ScanResult
    from ojs_sast.models.report import ScanReport

    data = ScanReport.from_scan_result(
        ScanResult(metadata={}, findings=[finding])
    ).to_dict()["findings"][0]

    assert data["ground_truth"] is True
    assert data["evaluation_scope"] == "ground_truth"
    assert data["rule_origin"] == "manual"
    assert data["rule_family"] == "xss"
