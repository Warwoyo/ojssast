"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_report_dict(), indent=2, ensure_ascii=False)


def write_json_report(result: ScanResult, output_dir: Path, filename: str = "findings.json") -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(render_json(result), encoding="utf-8")
    return path
