"""Tests for the YAML ruleset loader."""

import re

import pytest

from ojs_sast.models import Severity
from ojs_sast.ruleset.loader import RulesetError, load_ruleset


def test_loads_expected_modules(ruleset):
    counts = ruleset.counts_by_module()
    assert counts["source_code"] >= 6
    assert counts["config"] >= 12
    assert counts["upload_directory"] >= 5
    assert len(ruleset) == sum(counts.values())


def test_rule_ids_unique(ruleset):
    ids = [r.id for r in ruleset]
    assert len(ids) == len(set(ids))


def test_required_source_rules_present(ruleset):
    for rid in ("RULE-SRC-001", "RULE-SRC-002", "RULE-SRC-003",
                "RULE-SRC-004", "RULE-SRC-005", "RULE-SRC-006"):
        assert ruleset.get(rid) is not None, rid


def test_all_regex_patterns_compile(ruleset):
    for rule in ruleset:
        if rule.pattern_type == "regex" and rule.pattern:
            re.compile(rule.pattern)  # raises on failure
        for exc in rule.false_positive_exceptions:
            if exc.get("pattern"):
                re.compile(exc["pattern"])


def test_severities_parsed(ruleset):
    assert ruleset.get("RULE-SRC-005").severity is Severity.CRITICAL
    assert ruleset.get("RULE-SRC-001").severity is Severity.HIGH


def test_breached_password_list_embedded(ruleset):
    rule = ruleset.get("OJS-CFG-DB-001")
    pws = rule.params["breached_passwords"]
    assert len(pws) >= 50
    assert "password" in {p.lower() for p in pws}


def test_missing_directory_raises():
    with pytest.raises(RulesetError):
        load_ruleset("/nonexistent/ruleset/dir")


def test_duplicate_rule_id_raises(tmp_path):
    (tmp_path / "a_rules.yaml").write_text(
        "rules:\n  - {id: DUP, name: x, module: config, severity: LOW, pattern_type: builtin}\n")
    (tmp_path / "b_rules.yaml").write_text(
        "rules:\n  - {id: DUP, name: y, module: config, severity: LOW, pattern_type: builtin}\n")
    with pytest.raises(RulesetError):
        load_ruleset(tmp_path)


def test_invalid_module_raises(tmp_path):
    (tmp_path / "x_rules.yaml").write_text(
        "rules:\n  - {id: R1, name: x, module: bogus, severity: LOW}\n")
    with pytest.raises(RulesetError):
        load_ruleset(tmp_path)
