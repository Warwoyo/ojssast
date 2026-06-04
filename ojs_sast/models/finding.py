"""Reporter-facing finding model.

This is the *presentation* shape consumed by the reporters (JSON / HTML / SARIF)
and the HTML template. It is intentionally separate from the internal
:class:`ojs_sast.models.Finding` produced by the detectors — the orchestrator
adapts the internal findings into these objects via
:meth:`ojs_sast.models.report.ScanReport.from_scan_result`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ojs_sast.models import Severity, resolve_rule_metadata


class Category(Enum):
    """Top-level category a finding belongs to.

    Values match the ``data-category`` / filter values used by the HTML
    template (``source_code``, ``config``, ``uploaded_file``).
    """

    SOURCE_CODE = "source_code"
    CONFIG = "config"
    UPLOADED_FILE = "uploaded_file"


@dataclass
class TaintPath:
    """A source-to-sink data flow attached to a finding."""

    source: str
    source_location: str
    sink: str
    sink_location: str
    intermediate_steps: List[str] = field(default_factory=list)
    sanitized: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "source_location": self.source_location,
            "sink": self.sink,
            "sink_location": self.sink_location,
            "intermediate_steps": list(self.intermediate_steps),
            "sanitized": self.sanitized,
        }


@dataclass
class Finding:
    """A normalized finding as presented in reports."""

    rule_id: str
    name: str
    severity: Severity
    category: Category
    file_path: str
    line_start: int = 0
    line_end: int = 0
    description: str = ""
    remediation: str = ""
    subcategory: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    references: List[str] = field(default_factory=list)
    code_snippet: Optional[str] = None
    taint_path: Optional[TaintPath] = None
    confidence: str = "medium"
    cvss_score: Optional[float] = None
    ground_truth: Optional[bool] = None
    evaluation_scope: Optional[str] = None
    rule_origin: Optional[str] = None
    rule_family: Optional[str] = None
    applicable: Optional[bool] = None
    applicability_reason: Optional[str] = None
    # CVE-specific evidence carried through from the CVE scanner so the reporters
    # and HTML template can present the structured detection rationale.
    matched_source: Optional[str] = None
    matched_sink: Optional[str] = None
    missing_patch_evidence: Optional[str] = None
    safe_patch_checked: Optional[List[str]] = None
    affected_version_reasoning: Optional[str] = None
    confidence_reason: Optional[str] = None

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
            "finding_id": f"{self.rule_id}:{self.file_path}:{self.line_start}",
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss_score": self.cvss_score,
            "references": list(self.references),
            "code_snippet": self.code_snippet,
            "ground_truth": ground_truth,
            "evaluation_scope": evaluation_scope,
            "rule_origin": rule_origin,
            "rule_family": rule_family,
            "applicable": self.applicable,
            "applicability_reason": self.applicability_reason,
            "confidence": self.confidence,
            "taint_path": self.taint_path.to_dict() if self.taint_path else None,
            # CVE evidence (only present for CVE-scanner findings).
            **({"matched_source": self.matched_source} if self.matched_source else {}),
            **({"matched_sink": self.matched_sink} if self.matched_sink else {}),
            **({"missing_patch_evidence": self.missing_patch_evidence} if self.missing_patch_evidence else {}),
            **({"safe_patch_checked": self.safe_patch_checked} if self.safe_patch_checked else {}),
            **({"affected_version_reasoning": self.affected_version_reasoning} if self.affected_version_reasoning else {}),
            **({"confidence_reason": self.confidence_reason} if self.confidence_reason else {}),
        }
