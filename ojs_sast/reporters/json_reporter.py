"""JSON report generator for OJS-SAST."""

import json
import os

from ojs_sast.models.report import ScanReport
from ojs_sast.utils.logger import logger


def generate_json_report(report: ScanReport, output_dir: str) -> str:
    """Generate a JSON report file.

    Args:
        report: The scan report data.
        output_dir: Directory to write the report to.

    Returns:
        Path to the generated report file.
    """
    filepath = os.path.join(output_dir, "report.json")

    report_data = report.to_dict()

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"JSON report generated: {filepath}")
    except OSError as e:
        logger.error(f"Failed to write JSON report: {e}")

    return filepath
