"""HTML report generator for OJS-SAST using Jinja2."""

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ojs_sast.models.report import ScanReport
from ojs_sast.utils.logger import logger


def generate_html_report(report: ScanReport, output_dir: str) -> str:
    """Generate an interactive HTML report.

    Args:
        report: The scan report data.
        output_dir: Directory to write the report to.

    Returns:
        Path to the generated report file.
    """
    filepath = os.path.join(output_dir, "report.html")

    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html.j2")

    # Prepare template data
    findings_data = [f.to_dict() for f in report.findings]

    # Group findings by category
    by_category: dict[str, list] = {}
    for f in findings_data:
        cat = f["category"]
        by_category.setdefault(cat, []).append(f)

    # Group findings by severity
    by_severity: dict[str, list] = {}
    for f in findings_data:
        sev = f["severity"]
        by_severity.setdefault(sev, []).append(f)

    html_content = template.render(
        report=report.to_dict(),
        findings=findings_data,
        by_category=by_category,
        by_severity=by_severity,
        summary=report.summary,
    )

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report generated: {filepath}")
    except OSError as e:
        logger.error(f"Failed to write HTML report: {e}")

    return filepath
