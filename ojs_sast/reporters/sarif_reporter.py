"""SARIF 2.1.0 report writer (GitHub Advanced Security compatible)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from .. import __version__
from ..models import SARIF_LEVEL, ScanResult, Severity, sort_findings

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

INFO_URI = "https://github.com/ojs-sast/ojs-sast"


def _cwe_help_uri(cwe: str) -> str:
    num = cwe.upper().replace("CWE-", "").strip()
    if num.isdigit():
        return f"https://cwe.mitre.org/data/definitions/{num}.html"
    return INFO_URI


def _build_rules(findings) -> List[Dict[str, Any]]:
    rules: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        tags = ["security"]
        if f.cwe:
            tags.append(f"external/cwe/{f.cwe.lower()}")
        if f.owasp:
            tags.append(f"owasp/{f.owasp}")
        props: Dict[str, Any] = {
            "security-severity": (str(f.cvss_score) if f.cvss_score is not None
                                  else _SECURITY_SEVERITY[f.severity]),
            "tags": tags,
            "module": f.module,
        }
        if f.cwe:
            props["cwe"] = f.cwe
        if f.cve_references:
            props["cve"] = list(f.cve_references)
        rule_entry = {
            "id": f.rule_id,
            "name": "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", f.title)) or f.rule_id,
            "shortDescription": {"text": f.title or f.rule_id},
            "fullDescription": {"text": (f.detail or f.title or f.rule_id)[:1000]},
            "helpUri": _cwe_help_uri(f.cwe) if f.cwe else INFO_URI,
            "help": {"text": f.remediation or "See description."},
            "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
            "properties": props,
        }
        rules[f.rule_id] = rule_entry
    return list(rules.values())


def _build_result(f) -> Dict[str, Any]:
    location: Dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.file_path},
        }
    }
    if f.line is not None and f.line >= 1:
        region: Dict[str, Any] = {"startLine": f.line}
        if f.column is not None and f.column >= 1:
            region["startColumn"] = f.column
        if f.code_snippet:
            region["snippet"] = {"text": f.code_snippet}
        location["physicalLocation"]["region"] = region

    props: Dict[str, Any] = {"severity": f.severity.value, "confidence": f.confidence}
    if f.cwe:
        props["cwe"] = f.cwe
    if f.layer:
        props["layer"] = f.layer
    if f.taint_source:
        props["taint_source"] = f.taint_source
    if f.actual_mime:
        props["actual_mime"] = f.actual_mime

    return {
        "ruleId": f.rule_id,
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f.detail or f.title or f.rule_id},
        "locations": [location],
        "partialFingerprints": {"ojsSastFindingId": f.finding_id},
        "properties": props,
    }


def render_sarif(result: ScanResult) -> str:
    findings = sort_findings(result.findings)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ojs-sast",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": _build_rules(findings),
                    }
                },
                "results": [_build_result(f) for f in findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def write_sarif_report(result: ScanResult, output_dir: Path, filename: str = "findings.sarif") -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(render_sarif(result), encoding="utf-8")
    return path
