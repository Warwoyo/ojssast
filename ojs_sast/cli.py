"""Click CLI entry point for ojs-sast."""

from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .models import SEVERITY_ORDER, ScanResult, Severity
from .models.bundle import ScanBundle, resolve_source_root
from .orchestrator import Orchestrator
from .ruleset.loader import RulesetError, load_ruleset
from .service.extract import UnsafeArchiveError, safe_extract_archive

console = Console()

_SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}
_VALID_CATEGORIES = {"source_code", "config", "upload_directory"}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
    )


def _parse_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version-flag", prog_name="ojs-sast")
def cli() -> None:
    """ojs-sast — OJS-aware Extended Static Application Security Testing CLI."""


@cli.command()
@click.argument("ojs_path", type=click.Path(file_okay=False, path_type=Path))
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./ojs_sast_report"),
              show_default=True, help="Where to write reports.")
@click.option("--format", "fmt", default="json,html", show_default=True,
              help="Report formats (comma-separated): json,html,sarif.")
@click.option("--severity", "min_severity", default="INFO", show_default=True,
              type=click.Choice([s.value for s in SEVERITY_ORDER], case_sensitive=False),
              help="Minimum severity to report.")
@click.option("--category", default=None,
              help="Limit to categories (comma-separated): source_code,config,upload_directory.")
@click.option("--upload-dir", type=click.Path(path_type=Path), default=None,
              help="Override upload directory (skips config.inc.php lookup).")
@click.option("--skip-source", is_flag=True, help="Skip source code scanning.")
@click.option("--skip-config", is_flag=True, help="Skip configuration scanning.")
@click.option("--skip-upload", is_flag=True, help="Skip upload directory scanning.")
@click.option("--nginx-config", type=click.Path(path_type=Path), default=None,
              help="Path to an Nginx config file or directory.")
@click.option("--ruleset-dir", type=click.Path(file_okay=False, path_type=Path), default=None,
              help="Custom ruleset directory.")
@click.option("--ojs-version", default=None, help='Force OJS version (e.g. "3.3.0-13").')
@click.option("--verbose", is_flag=True, help="Show detailed progress.")
def scan(ojs_path: Path, output_dir: Path, fmt: str, min_severity: str,
         category: Optional[str], upload_dir: Optional[Path], skip_source: bool,
         skip_config: bool, skip_upload: bool, nginx_config: Optional[Path],
         ruleset_dir: Optional[Path], ojs_version: Optional[str], verbose: bool) -> None:
    """Scan an OJS deployment at OJS_PATH for security issues."""
    _setup_logging(verbose)

    if not ojs_path.exists() and not upload_dir:
        console.print(f"[bold red]Error:[/] path does not exist: {ojs_path}")
        sys.exit(2)

    categories = _parse_csv(category)
    invalid = [c for c in categories if c not in _VALID_CATEGORIES]
    if invalid:
        console.print(f"[bold red]Error:[/] invalid category/categories: {', '.join(invalid)}")
        sys.exit(2)

    formats = _parse_csv(fmt)
    bad_fmt = [f for f in formats if f not in {"json", "html", "sarif"}]
    if bad_fmt:
        console.print(f"[bold red]Error:[/] invalid format(s): {', '.join(bad_fmt)}")
        sys.exit(2)

    console.print(Panel.fit(
        f"[bold]ojs-sast[/] v{__version__}\nTarget: [cyan]{ojs_path}[/]",
        border_style="blue"))

    def progress(msg: str) -> None:
        console.print(f"  [dim]›[/] {msg}")

    try:
        orch = Orchestrator(
            ojs_path,
            ruleset_dir=ruleset_dir,
            output_dir=output_dir,
            formats=formats or ["json"],
            min_severity=Severity.from_str(min_severity),
            categories=categories or None,
            upload_dir_override=upload_dir,
            skip_source=skip_source,
            skip_config=skip_config,
            skip_upload=skip_upload,
            nginx_config=nginx_config,
            ojs_version=ojs_version,
            verbose=verbose,
            progress_cb=progress,
        )
        result = orch.run()
        written = orch.generate_reports(result)
    except RulesetError as exc:
        console.print(f"[bold red]Ruleset error:[/] {exc}")
        sys.exit(2)
    except Exception as exc:  # pragma: no cover - top-level guard
        console.print(f"[bold red]Scan failed:[/] {exc}")
        if verbose:
            console.print_exception()
        sys.exit(1)

    _print_summary(result)
    console.print()
    for fmt_name, path in written.items():
        console.print(f"  [green]✓[/] {fmt_name.upper()} report: [cyan]{path}[/]")


@cli.command(name="scan-bundle")
@click.option("--source", "source", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Path to the agent source.tar.gz.")
@click.option("--meta", "meta_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Path to the agent meta.json.")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./ojs_sast_report"),
              show_default=True, help="Where to write reports.")
@click.option("--format", "fmt", default="json,html", show_default=True,
              help="Report formats (comma-separated): json,html,sarif.")
@click.option("--severity", "min_severity", default="INFO", show_default=True,
              type=click.Choice([s.value for s in SEVERITY_ORDER], case_sensitive=False),
              help="Minimum severity to report.")
@click.option("--category", default=None,
              help="Limit to categories (comma-separated): source_code,config,upload_directory.")
@click.option("--ruleset-dir", type=click.Path(file_okay=False, path_type=Path), default=None,
              help="Custom ruleset directory.")
@click.option("--ojs-version", default=None, help="Force OJS version (overrides meta.json).")
@click.option("--verbose", is_flag=True, help="Show detailed progress.")
def scan_bundle(source: Path, meta_path: Path, output_dir: Path, fmt: str,
                min_severity: str, category: Optional[str], ruleset_dir: Optional[Path],
                ojs_version: Optional[str], verbose: bool) -> None:
    """Scan a local agent bundle (SOURCE tar.gz + META json) without a service."""
    _setup_logging(verbose)

    categories = _parse_csv(category)
    invalid = [c for c in categories if c not in _VALID_CATEGORIES]
    if invalid:
        console.print(f"[bold red]Error:[/] invalid category/categories: {', '.join(invalid)}")
        sys.exit(2)

    formats = _parse_csv(fmt)
    bad_fmt = [f for f in formats if f not in {"json", "html", "sarif"}]
    if bad_fmt:
        console.print(f"[bold red]Error:[/] invalid format(s): {', '.join(bad_fmt)}")
        sys.exit(2)

    try:
        meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[bold red]Error:[/] cannot read meta.json: {exc}")
        sys.exit(2)

    console.print(Panel.fit(
        f"[bold]ojs-sast[/] v{__version__}\nBundle: [cyan]{source}[/]",
        border_style="blue"))

    def progress(msg: str) -> None:
        console.print(f"  [dim]›[/] {msg}")

    result: Optional[ScanResult] = None
    written: dict = {}
    with tempfile.TemporaryDirectory(prefix="ojs-sast-bundle-") as tmp:
        extract_dir = Path(tmp) / "extracted"
        try:
            safe_extract_archive(source, extract_dir)
        except (UnsafeArchiveError, OSError) as exc:
            console.print(f"[bold red]Unsafe or unreadable archive:[/] {exc}")
            sys.exit(2)

        source_root = resolve_source_root(extract_dir, meta)
        bundle = ScanBundle.from_meta(meta, source_root)

        try:
            orch = Orchestrator(
                source_root or extract_dir,
                ruleset_dir=ruleset_dir,
                output_dir=output_dir,
                formats=formats or ["json"],
                min_severity=Severity.from_str(min_severity),
                categories=categories or None,
                ojs_version=ojs_version,
                verbose=verbose,
                progress_cb=progress,
            )
            result = orch.run_bundle(bundle)
            written = orch.generate_reports(result)
        except RulesetError as exc:
            console.print(f"[bold red]Ruleset error:[/] {exc}")
            sys.exit(2)
        except Exception as exc:  # pragma: no cover - top-level guard
            console.print(f"[bold red]Scan failed:[/] {exc}")
            if verbose:
                console.print_exception()
            sys.exit(1)

    _print_summary(result)
    console.print()
    for fmt_name, path in written.items():
        console.print(f"  [green]✓[/] {fmt_name.upper()} report: [cyan]{path}[/]")


def _print_summary(result: ScanResult) -> None:
    summary = result.summary()
    meta = result.metadata

    sev_table = Table(title="Findings by severity", title_style="bold", show_edge=True)
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    for sev in SEVERITY_ORDER:
        count = summary["by_severity"].get(sev.value, 0)
        style = _SEV_COLOR[sev.value] if count else "dim"
        sev_table.add_row(f"[{style}]{sev.value}[/]", str(count))
    sev_table.add_row("[bold]TOTAL[/]", f"[bold]{summary['total_findings']}[/]")

    mod_table = Table(title="Findings by module", title_style="bold")
    mod_table.add_column("Module")
    mod_table.add_column("Count", justify="right")
    for mod, count in sorted(summary["by_module"].items()):
        mod_table.add_row(mod, str(count))
    if not summary["by_module"]:
        mod_table.add_row("[dim]none[/]", "0")

    console.print()
    console.print(sev_table)
    console.print(mod_table)
    console.print(
        f"[dim]OJS version: {meta['ojs_version']} · rules: {meta['rules_loaded']} · "
        f"files scanned: {meta.get('files_scanned', {})} · "
        f"{meta['duration_seconds']}s[/]"
    )

    # Show the most severe findings inline.
    top = [f for f in result.findings if f.severity.rank >= Severity.HIGH.rank][:12]
    if top:
        t = Table(title="Top findings (CRITICAL/HIGH)", title_style="bold red")
        t.add_column("Sev"); t.add_column("Rule"); t.add_column("Location"); t.add_column("Title")
        for f in top:
            loc = f.file_path + (f":{f.line}" if f.line else "")
            t.add_row(f"[{_SEV_COLOR[f.severity.value]}]{f.severity.value}[/]",
                      f.rule_id, loc, f.title)
        console.print(t)


@cli.command(name="list-rules")
@click.option("--ruleset-dir", type=click.Path(file_okay=False, path_type=Path), default=None,
              help="Custom ruleset directory.")
@click.option("--module", default=None, help="Filter by module.")
def list_rules(ruleset_dir: Optional[Path], module: Optional[str]) -> None:
    """List all loaded rules with their metadata."""
    try:
        ruleset = load_ruleset(ruleset_dir)
    except RulesetError as exc:
        console.print(f"[bold red]Ruleset error:[/] {exc}")
        sys.exit(2)

    table = Table(title=f"ojs-sast ruleset ({len(ruleset)} rules)", title_style="bold")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Sev")
    table.add_column("Module")
    table.add_column("Type")
    table.add_column("CWE")
    table.add_column("Name")
    for rule in sorted(ruleset, key=lambda r: (r.module, r.id)):
        if module and rule.module != module:
            continue
        table.add_row(rule.id, f"[{_SEV_COLOR[rule.severity.value]}]{rule.severity.value}[/]",
                      rule.module, rule.pattern_type, rule.cwe or "-", rule.name)
    console.print(table)


@cli.command()
def version() -> None:
    """Show the tool version."""
    console.print(f"ojs-sast {__version__}")


if __name__ == "__main__":  # pragma: no cover
    cli()
