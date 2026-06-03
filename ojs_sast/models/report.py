"""Reporter-facing scan report model.

:class:`ScanReport` is the top-level object handed to every reporter. It is
built from the internal :class:`ojs_sast.models.ScanResult` produced by the
orchestrator via :meth:`ScanReport.from_scan_result`, which maps the detector
findings onto the presentation :class:`ojs_sast.models.finding.Finding` shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List

from ojs_sast.constants import __version__
from ojs_sast.models.finding import Category, Finding

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ojs_sast.models import Finding as InternalFinding
    from ojs_sast.models import ScanResult

# Canonical severity ordering used to seed the summary counters so the keys are
# always present (and ordered) for the template / charts.
_SEVERITY_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Internal detector module names map onto the presentation categories used by
# the HTML template filters.
_MODULE_TO_CATEGORY = {
    "source_code": Category.SOURCE_CODE,
    "config": Category.CONFIG,
    "upload_directory": Category.UPLOADED_FILE,
}


def _to_finding(internal: "InternalFinding") -> Finding:
    """Adapt an internal detector finding into the reporter-facing shape."""
    line = internal.line or 0
    return Finding(
        rule_id=internal.rule_id,
        name=internal.title or internal.rule_id,
        severity=internal.severity,
        category=_MODULE_TO_CATEGORY.get(internal.module, Category.SOURCE_CODE),
        file_path=internal.file_path,
        line_start=line,
        line_end=line,
        description=internal.detail or "",
        remediation=internal.remediation or "",
        subcategory=internal.layer or "",
        cwe=internal.cwe,
        owasp=internal.owasp,
        references=list(internal.cve_references or []),
        code_snippet=internal.code_snippet,
        taint_path=None,
        confidence=internal.confidence,
        cvss_score=internal.cvss_score,
    )


@dataclass
class ScanReport:
    """The presentation-level report passed to the reporters."""

    findings: List[Finding] = field(default_factory=list)
    timestamp: str = ""
    ojs_path: str = ""
    ojs_version: str = ""
    scan_duration_seconds: float = 0.0
    files_scanned: int = 0
    rules_loaded: int = 0
    scanner_version: str = __version__
    summary: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_scan_result(cls, result: "ScanResult") -> "ScanReport":
        """Build a report from the orchestrator's internal scan result."""
        meta = result.metadata or {}
        findings = [_to_finding(f) for f in result.findings]

        summary: Dict[str, int] = {k: 0 for k in _SEVERITY_KEYS}
        for f in findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

        files = meta.get("files_scanned", {})
        if isinstance(files, dict):
            files_scanned = sum(int(v) for v in files.values())
        else:
            files_scanned = int(files or 0)

        return cls(
            findings=findings,
            timestamp=meta.get("scan_timestamp", ""),
            ojs_path=meta.get("ojs_path", ""),
            ojs_version=meta.get("ojs_version", ""),
            scan_duration_seconds=float(meta.get("duration_seconds", 0.0) or 0.0),
            files_scanned=files_scanned,
            rules_loaded=int(meta.get("rules_loaded", 0) or 0),
            scanner_version=meta.get("version", __version__),
            summary=summary,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_version": self.scanner_version,
            "timestamp": self.timestamp,
            "ojs_path": self.ojs_path,
            "ojs_version": self.ojs_version,
            "scan_duration_seconds": self.scan_duration_seconds,
            "files_scanned": self.files_scanned,
            "rules_loaded": self.rules_loaded,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
