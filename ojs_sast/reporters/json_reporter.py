"""JSON report generator for OJS-SAST."""

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from ojs_sast.models.report import ScanReport
from ojs_sast.utils.logger import logger

if TYPE_CHECKING:
    from ojs_sast.models import ScanResult


def generate_json_report(report: ScanReport, output_dir: str) -> str:
    """Generate a JSON report file.

    Args:
        report: The scan report data.
        output_dir: Directory to write the report to.

    Returns:
        Path to the generated report file.
    """
    filepath = os.path.join(output_dir, "findings.json")

    report_data = report.to_dict()

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"JSON report generated: {filepath}")
    except OSError as e:
        logger.error(f"Failed to write JSON report: {e}")

    return filepath


def render_json(result: "ScanResult") -> str:
    """Render a JSON report string from an internal ScanResult."""
    data = result.to_report_dict()
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def write_json_report(result: "ScanResult", output_dir) -> Path:
    """Write a JSON report to disk and return the Path."""
    text = render_json(result)
    out = Path(output_dir) / "findings.json"
    out.write_text(text, encoding="utf-8")
    return out
