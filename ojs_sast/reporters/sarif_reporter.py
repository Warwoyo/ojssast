"""SARIF 2.1.0 report generator for OJS-SAST.

Generates reports compatible with GitHub Code Scanning and VS Code SARIF Viewer.
"""

import json
import os

from ojs_sast.constants import __version__
from ojs_sast.models.finding import Finding
from ojs_sast.models.report import ScanReport
from ojs_sast.utils.logger import logger

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def generate_sarif_report(report: ScanReport, output_dir: str) -> str:
    """Generate a SARIF 2.1.0 report.

    Args:
        report: The scan report data.
        output_dir: Directory to write the report to.

    Returns:
        Path to the generated report file.
    """
    filepath = os.path.join(output_dir, "report.sarif")

    # Collect unique rules used in findings
    rules_map: dict[str, dict] = {}
    for finding in report.findings:
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = _build_rule(finding)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OJS-SAST",
                        "version": __version__,
                        "informationUri": "https://github.com/ojs-sast/ojs-sast",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": [_build_result(f) for f in report.findings],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": report.timestamp,
                    }
                ],
            }
        ],
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        logger.info(f"SARIF report generated: {filepath}")
    except OSError as e:
        logger.error(f"Failed to write SARIF report: {e}")

    return filepath


def _build_rule(finding: Finding) -> dict:
    """Build a SARIF rule descriptor from a finding."""
    rule: dict = {
        "id": finding.rule_id,
        "name": finding.name,
        "shortDescription": {"text": finding.name},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {
            "level": _severity_to_level(finding.severity.value),
        },
        "helpUri": finding.references[0] if finding.references else "",
    }

    rule["properties"] = {
        "tags": [finding.category.value, finding.subcategory],
    }
    
    if finding.cwe:
        rule["properties"]["tags"].append(finding.cwe)
    if finding.owasp:
        rule["properties"]["tags"].append(finding.owasp)

    return rule


def _build_result(finding: Finding) -> dict:
    """Build a SARIF result from a finding."""
    result: dict = {
        "ruleId": finding.rule_id,
        "level": _severity_to_level(finding.severity.value),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path,
                    },
                    "region": {
                        "startLine": max(1, finding.line_start),
                        "endLine": max(1, finding.line_end),
                    },
                }
            }
        ],
    }

    # Add code snippet
    if finding.code_snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.code_snippet,
        }

    # Add taint path as code flow
    if finding.taint_path:
        tp = finding.taint_path
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {"text": f"Source: {tp.source}"},
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": tp.source_location.rsplit(":", 1)[0]},
                                        "region": {"startLine": int(tp.source_location.rsplit(":", 1)[1]) if ":" in tp.source_location else 1},
                                    },
                                }
                            },
                            *[
                                {
                                    "location": {
                                        "message": {"text": step},
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": finding.file_path},
                                        },
                                    }
                                }
                                for step in tp.intermediate_steps
                            ],
                            {
                                "location": {
                                    "message": {"text": f"Sink: {tp.sink}"},
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": tp.sink_location.rsplit(":", 1)[0]},
                                        "region": {"startLine": int(tp.sink_location.rsplit(":", 1)[1]) if ":" in tp.sink_location else 1},
                                    },
                                }
                            },
                        ]
                    }
                ]
            }
        ]

    # Add fix/remediation
    if finding.remediation:
        result["fixes"] = [
            {
                "description": {"text": finding.remediation},
            }
        ]

    return result


def _severity_to_level(severity: str) -> str:
    """Map OJS-SAST severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity, "warning")
