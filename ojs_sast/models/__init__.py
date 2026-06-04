"""Core data models for ojs-sast: Severity, Rule, RuleMatch, Finding."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(Enum):
    """Finding severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank where higher means more severe (CRITICAL=5 ... INFO=1)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse a severity from a (case-insensitive) string."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {value!r}") from exc

    def __ge__(self, other: "Severity") -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


_MODULE_TO_CATEGORY = {
    "source_code": "source_code",
    "config": "config",
    "upload_directory": "uploaded_file",
}


def category_for_module(module: str) -> str:
    """Return the reporter-facing category for an internal scanner module."""
    return _MODULE_TO_CATEGORY.get(module, module)


# SARIF maps severities onto level + security-severity (CVSS-like) values.
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass
class Rule:
    """A single detection rule loaded from a YAML ruleset."""

    id: str
    name: str
    module: str  # source_code | config | upload_directory
    severity: Severity
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    pattern_type: str = "regex"  # regex | smarty | ast | taint | builtin
    pattern: Optional[str] = None
    description: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    cve_references: List[str] = field(default_factory=list)
    file_extensions: List[str] = field(default_factory=list)
    false_positive_exceptions: List[Dict[str, Any]] = field(default_factory=list)
    # Arbitrary rule-specific parameters (e.g. min_length, default_values, signatures).
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "module": self.module,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "pattern_type": self.pattern_type,
            "description": self.description,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cve_references": list(self.cve_references),
            "file_extensions": list(self.file_extensions),
        }


def resolve_rule_metadata(rule_id: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolve evaluation metadata for a rule id and optional rule params.

    Rule params may explicitly override the default ground-truth/scope mapping
    and can also provide optional reporting classifiers such as rule_origin and
    rule_family.
    """
    params = params or {}
    metadata: Dict[str, Any] = {
        "ground_truth": None,
        "evaluation_scope": None,
        "rule_origin": None,
        "rule_family": None,
    }

    if rule_id.startswith("CVE-SRC-"):
        metadata.update(ground_truth=True, evaluation_scope="ground_truth")
    elif rule_id.startswith(("OJS-CFG-NGX-", "OJS-CFG-EXT-")):
        metadata.update(ground_truth=False, evaluation_scope="extension")
    elif rule_id.startswith("OJS-CFG-"):
        metadata.update(ground_truth=True, evaluation_scope="ground_truth")
    elif rule_id.startswith("RULE-UPLOAD-"):
        metadata.update(ground_truth=False, evaluation_scope="upload")
    elif rule_id.startswith("RULE-SRC-"):
        metadata.update(ground_truth=False, evaluation_scope="generic")

    for key in ("ground_truth", "evaluation_scope", "rule_origin", "rule_family"):
        if key in params and params[key] is not None:
            metadata[key] = params[key]

    return metadata


@dataclass
class RuleMatch:
    """A raw match produced by the regex/AST engines before becoming a Finding."""

    rule: Rule
    file_path: str
    line: int
    snippet: str = ""
    column: Optional[int] = None
    detail: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A normalized security finding produced by any detector module."""

    rule_id: str
    module: str  # source_code | config | upload_directory
    severity: Severity
    file_path: str
    title: str = ""
    detail: str = ""
    remediation: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_references: List[str] = field(default_factory=list)
    code_snippet: Optional[str] = None
    ground_truth: Optional[bool] = None
    evaluation_scope: Optional[str] = None
    rule_origin: Optional[str] = None
    rule_family: Optional[str] = None
    # Version-aware applicability (set by detectors that know the OJS version).
    # ``applicable`` answers: does this rule apply to the scanned OJS version?
    # It is independent of ``ground_truth`` (dataset membership).
    applicable: Optional[bool] = None
    applicability_reason: Optional[str] = None

    # Module-specific fields (kept optional so the schema stays uniform).
    layer: Optional[str] = None  # upload module layer
    actual_mime: Optional[str] = None
    declared_extension: Optional[str] = None
    taint_source: Optional[str] = None  # source label for taint findings
    confidence: str = "medium"  # low | medium | high
    # Optional extra discriminator so legitimately distinct findings that share
    # (rule_id, file_path, line) — e.g. one per missing Nginx header — are not
    # merged during de-duplication.
    dedup_discriminator: Optional[str] = None

    # CVE-specific evidence fields (populated by CVE scanner, optional for others).
    matched_source: Optional[str] = None
    matched_sink: Optional[str] = None
    missing_patch_evidence: Optional[str] = None
    safe_patch_checked: Optional[List[str]] = None
    affected_version_reasoning: Optional[str] = None
    confidence_reason: Optional[str] = None

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> Tuple[str, str, Optional[int], Optional[str]]:
        """Findings sharing this key are considered duplicates."""
        return (self.rule_id, self.file_path, self.line, self.dedup_discriminator)

    @classmethod
    def from_match(cls, match: RuleMatch) -> "Finding":
        """Build a Finding from a RuleMatch, inheriting metadata from the rule."""
        rule = match.rule
        return cls(
            rule_id=rule.id,
            module=rule.module,
            severity=rule.severity,
            file_path=match.file_path,
            title=rule.name,
            detail=match.detail or rule.description,
            remediation=rule.remediation,
            line=match.line,
            column=match.column,
            cwe=rule.cwe,
            owasp=rule.owasp,
            cvss_score=rule.cvss_score,
            cve_references=list(rule.cve_references),
            code_snippet=match.snippet or None,
            **resolve_rule_metadata(rule.id, rule.params),
            extra=dict(match.extra),
        )

    def to_dict(self) -> Dict[str, Any]:
        metadata = resolve_rule_metadata(self.rule_id)
        ground_truth = (
            self.ground_truth if self.ground_truth is not None else metadata["ground_truth"]
        )
        evaluation_scope = (
            self.evaluation_scope
            if self.evaluation_scope is not None
            else metadata["evaluation_scope"]
        )
        rule_origin = self.rule_origin if self.rule_origin is not None else metadata["rule_origin"]
        rule_family = self.rule_family if self.rule_family is not None else metadata["rule_family"]
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "module": self.module,
            "severity": self.severity.value,
            "category": category_for_module(self.module),
            "file_path": self.file_path,
            "line": self.line,
            "line_start": self.line or 0,
            "column": self.column,
            "title": self.title,
            "name": self.title or self.rule_id,
            "detail": self.detail,
            "description": self.detail or "",
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss_score": self.cvss_score,
            "cve_references": list(self.cve_references),
            "references": list(self.cve_references),
            "code_snippet": self.code_snippet,
            "ground_truth": ground_truth,
            "evaluation_scope": evaluation_scope,
            "rule_origin": rule_origin,
            "rule_family": rule_family,
            "applicable": self.applicable,
            "applicability_reason": self.applicability_reason,
            "layer": self.layer,
            "actual_mime": self.actual_mime,
            "declared_extension": self.declared_extension,
            "taint_source": self.taint_source,
            "confidence": self.confidence,
            "remediation": self.remediation,
            # CVE evidence fields (omitted when None for backward compat).
            **({"matched_source": self.matched_source} if self.matched_source else {}),
            **({"matched_sink": self.matched_sink} if self.matched_sink else {}),
            **({"missing_patch_evidence": self.missing_patch_evidence} if self.missing_patch_evidence else {}),
            **({"safe_patch_checked": self.safe_patch_checked} if self.safe_patch_checked else {}),
            **({"affected_version_reasoning": self.affected_version_reasoning} if self.affected_version_reasoning else {}),
            **({"confidence_reason": self.confidence_reason} if self.confidence_reason else {}),
            **({"extra": self.extra} if self.extra else {}),
        }


# Canonical ordering of modules and severities for reporting.
MODULE_ORDER = ["source_code", "config", "upload_directory"]
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def sort_findings(findings: List["Finding"]) -> List["Finding"]:
    """Sort by severity (desc), then module, file, line."""
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            MODULE_ORDER.index(f.module) if f.module in MODULE_ORDER else 99,
            f.file_path or "",
            f.line if f.line is not None else -1,
            f.rule_id,
        ),
    )


@dataclass
class ScanResult:
    """Holds the metadata and findings of a completed scan."""

    metadata: Dict[str, Any]
    findings: List["Finding"] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {s.value: 0 for s in SEVERITY_ORDER}
        by_module: Dict[str, int] = {}
        for f in self.findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_module[f.module] = by_module.get(f.module, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "by_module": by_module,
        }

    def to_report_dict(self) -> Dict[str, Any]:
        return {
            "scan_metadata": self.metadata,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in sort_findings(self.findings)],
        }
