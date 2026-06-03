#!/usr/bin/env python3
"""Evaluate OJS-SAST JSON scan results against ground-truth rule IDs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ojs_sast.models import resolve_rule_metadata

DEFAULT_RULESET_DIR = REPO_ROOT / "ojs_sast" / "ruleset"

RULE_ID_RE = re.compile(r"\b(?:OJS-CFG|CVE-SRC|RULE-SRC|RULE-UPLOAD)-[A-Z0-9_-]+\b")
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
STRICT_EXCLUDED_RULE_IDS = {"RULE-SRC-010", "RULE-SRC-011", "RULE-SRC-012"}
STRICT_EXCLUDED_PREFIXES = ("RULE-UPLOAD-", "OJS-CFG-NGX-", "OJS-CFG-EXT-")
UPLOAD_PREFIXES = ("RULE-UPLOAD-",)
EXTENSION_SCOPES = {"extension"}
GENERIC_SCOPES = {"generic"}


def load_json(path: Path) -> Any:
    """Load JSON from *path* with a path-aware error message."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse JSON {path}: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Failed to read {path}: {exc}") from exc


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def _extract_rule_ids(value: Any) -> set[str]:
    rule_ids: set[str] = set()
    for text in _iter_strings(value):
        rule_ids.update(match.group(0) for match in RULE_ID_RE.finditer(text))
    return rule_ids


def _extract_cve_ids(value: Any) -> set[str]:
    cve_ids: set[str] = set()
    for text in _iter_strings(value):
        cve_ids.update(match.group(0).upper() for match in CVE_ID_RE.finditer(text))
    return cve_ids


def _load_ruleset_records(ruleset_dir: Path | None) -> list[dict[str, Any]]:
    """Load lightweight rule records from ruleset YAML files.

    PyYAML is used when available. A small line-oriented fallback keeps the
    evaluator usable in minimal test/runtime environments where optional
    project dependencies have not been installed yet.
    """
    directory = Path(ruleset_dir or DEFAULT_RULESET_DIR)
    records: list[dict[str, Any]] = []

    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        yaml = None

    if yaml is not None:
        for rule_file in sorted(directory.glob("*_rules.yaml")):
            data = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
            for raw in data.get("rules", []) or []:
                params = raw.get("params", {}) or {}
                records.append(
                    {
                        "id": str(raw.get("id", "")),
                        "severity": str(raw.get("severity", "")),
                        "cve_references": list(raw.get("cve_references", []) or []),
                        "cve_id": str(params.get("cve_id", "")) if params.get("cve_id") else "",
                    }
                )
        return records

    for rule_file in sorted(directory.glob("*_rules.yaml")):
        current: dict[str, Any] | None = None
        in_cve_references = False
        in_params = False
        for raw_line in rule_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("- id:"):
                if current:
                    records.append(current)
                current = {
                    "id": line.split(":", 1)[1].strip().strip('"\''),
                    "severity": "",
                    "cve_references": [],
                    "cve_id": "",
                }
                in_cve_references = False
                in_params = False
                continue
            if current is None:
                continue
            if line.startswith("severity:"):
                current["severity"] = line.split(":", 1)[1].strip().strip('"\'')
                in_cve_references = False
                continue
            if line.startswith("cve_references:"):
                in_cve_references = True
                current["cve_references"].extend(_extract_cve_ids(line))
                continue
            if in_cve_references and line.startswith("-"):
                current["cve_references"].extend(_extract_cve_ids(line))
                continue
            if line.startswith("params:"):
                in_params = True
                in_cve_references = False
                continue
            if in_params and line.startswith("cve_id:"):
                cves = _extract_cve_ids(line)
                current["cve_id"] = next(iter(cves), "")
                continue
            if line and not raw_line.startswith(" "):
                in_cve_references = False
                in_params = False
        if current:
            records.append(current)
    return records


def _build_cve_rule_map(ruleset_dir: Path | None) -> dict[str, set[str]]:
    cve_to_rules: dict[str, set[str]] = {}
    for rule in _load_ruleset_records(ruleset_dir):
        rule_id = rule.get("id", "")
        if not rule_id:
            continue
        candidate_cves = set(rule.get("cve_references", []))
        cve_id = rule.get("cve_id")
        if cve_id:
            candidate_cves.add(str(cve_id))
        for cve in candidate_cves:
            cve_to_rules.setdefault(cve.upper(), set()).add(rule_id)
    return cve_to_rules


def _build_rule_severity_map(ruleset_dir: Path | None) -> dict[str, str]:
    return {
        str(rule.get("id")): str(rule.get("severity"))
        for rule in _load_ruleset_records(ruleset_dir)
        if rule.get("id")
    }

def build_expected_rule_ids(
    gt_config: Any,
    gt_cve: Any,
    ruleset_dir: Path | None = None,
    exclude_informational_gt: bool = False,
) -> set[str]:
    """Build the expected ground-truth rule-id set from config and CVE JSON."""
    expected = _extract_rule_ids(gt_config) | _extract_rule_ids(gt_cve)

    cve_to_rules = _build_cve_rule_map(ruleset_dir)
    for cve_id in _extract_cve_ids(gt_cve):
        expected.update(cve_to_rules.get(cve_id, set()))

    if exclude_informational_gt:
        severity_by_rule = _build_rule_severity_map(ruleset_dir)
        expected = {rule_id for rule_id in expected if severity_by_rule.get(rule_id) != "INFO"}

    return expected


def extract_findings(scan_result: Any) -> list[dict[str, Any]]:
    """Extract reporter findings from the current JSON reporter structure."""
    if isinstance(scan_result, dict):
        findings = scan_result.get("findings", [])
        if isinstance(findings, list):
            return [finding for finding in findings if isinstance(finding, dict)]
    if isinstance(scan_result, list):
        return [finding for finding in scan_result if isinstance(finding, dict)]
    return []


def _rule_id(finding: dict[str, Any]) -> str:
    return str(finding.get("rule_id") or finding.get("ruleId") or finding.get("id") or "")


def is_upload_finding(finding: dict[str, Any]) -> bool:
    rule_id = _rule_id(finding)
    return rule_id.startswith(UPLOAD_PREFIXES) or finding.get("evaluation_scope") == "upload"


def is_strict_gt_finding(finding: dict[str, Any]) -> bool:
    rule_id = _rule_id(finding)
    return (
        bool(rule_id)
        and finding.get("ground_truth") is True
        and finding.get("evaluation_scope") == "ground_truth"
        and not rule_id.startswith(STRICT_EXCLUDED_PREFIXES)
        and rule_id not in STRICT_EXCLUDED_RULE_IDS
    )


def _finding_scope(finding: dict[str, Any]) -> str | None:
    scope = finding.get("evaluation_scope")
    if scope:
        return str(scope)
    return resolve_rule_metadata(_rule_id(finding))["evaluation_scope"]


def select_predicted_rule_ids(findings: list[dict[str, Any]], scope: str) -> set[str]:
    if scope in {"strict-gt", "extension-aware"}:
        selected = [finding for finding in findings if is_strict_gt_finding(finding)]
    elif scope == "all-reported":
        selected = [finding for finding in findings if not is_upload_finding(finding)]
    else:  # pragma: no cover - argparse enforces choices
        raise ValueError(f"Unknown scope: {scope}")
    return {_rule_id(finding) for finding in selected if _rule_id(finding)}


def summarize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    keys = ("rule_id", "name", "severity", "category", "file_path", "line_start", "evaluation_scope")
    return {key: finding.get(key) for key in keys if key in finding}


def extension_and_generic_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    extension: list[dict[str, Any]] = []
    generic: list[dict[str, Any]] = []
    for finding in findings:
        if is_upload_finding(finding):
            continue
        rule_id = _rule_id(finding)
        scope = _finding_scope(finding)
        if scope in EXTENSION_SCOPES or rule_id.startswith(("OJS-CFG-NGX-", "OJS-CFG-EXT-")):
            extension.append(summarize_finding(finding))
        elif scope in GENERIC_SCOPES or rule_id.startswith("RULE-SRC-"):
            generic.append(summarize_finding(finding))
    return extension, generic


def calculate_metrics(expected: set[str], predicted: set[str], scope: str) -> dict[str, Any]:
    tp_rules = predicted & expected
    fp_rules = predicted - expected
    fn_rules = expected - predicted

    tp = len(tp_rules)
    fp = len(fp_rules)
    fn = len(fn_rules)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "scope": scope,
        "total_gt": len(expected),
        "predicted": len(predicted),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positives": sorted(fp_rules),
        "false_negatives": sorted(fn_rules),
    }


def evaluate_scan_results(
    scan_result_paths: list[Path],
    ground_truth_config_path: Path,
    ground_truth_cve_path: Path,
    ruleset_dir: Path | None,
    scope: str,
    exclude_informational_gt: bool = False,
) -> dict[str, Any]:
    gt_config = load_json(ground_truth_config_path)
    gt_cve = load_json(ground_truth_cve_path)
    expected = build_expected_rule_ids(gt_config, gt_cve, ruleset_dir, exclude_informational_gt)

    findings: list[dict[str, Any]] = []
    for path in scan_result_paths:
        findings.extend(extract_findings(load_json(path)))

    predicted = select_predicted_rule_ids(findings, scope)
    result = calculate_metrics(expected, predicted, scope)

    if scope == "extension-aware":
        extension, generic = extension_and_generic_findings(findings)
        result["extension_findings"] = extension
        result["generic_findings"] = generic

    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_results", nargs="+", type=Path, help="One or more JSON scan results")
    parser.add_argument("--ground-truth-config", required=True, type=Path, help="Ground-truth config JSON")
    parser.add_argument("--ground-truth-cve", required=True, type=Path, help="Ground-truth CVE JSON")
    parser.add_argument("--ruleset-dir", type=Path, default=None, help="Optional ruleset directory")
    parser.add_argument(
        "--scope",
        choices=("strict-gt", "all-reported", "extension-aware"),
        default="strict-gt",
        help="Evaluation scope (default: strict-gt)",
    )
    parser.add_argument(
        "--exclude-informational-gt",
        action="store_true",
        help="Exclude INFO-severity ground-truth rules from expected metrics",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = evaluate_scan_results(
        scan_result_paths=args.scan_results,
        ground_truth_config_path=args.ground_truth_config,
        ground_truth_cve_path=args.ground_truth_cve,
        ruleset_dir=args.ruleset_dir,
        scope=args.scope,
        exclude_informational_gt=args.exclude_informational_gt,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
