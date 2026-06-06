"""``ojs-agent`` CLI — collect OJS artefacts and submit them to a service.

``build-bundle`` produces a local bundle (no network, no extra deps). ``scan``
builds a bundle and submits it to a remote OJS-SAST service (requires the
``agent`` extra for ``httpx``).
"""

from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import click

from . import AGENT_VERSION
from .bundle_builder import build_bundle

_VALID_CATEGORIES = {"source_code", "config", "upload_directory"}


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _parse_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def _load_api_key(api_key: Optional[str], api_key_file: Optional[Path]) -> Optional[str]:
    if api_key_file:
        return Path(api_key_file).read_text(encoding="utf-8").strip()
    return api_key


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(AGENT_VERSION, "-V", "--version-flag", prog_name="ojs-agent")
def cli() -> None:
    """ojs-agent — build and submit OJS-SAST scan bundles."""


@cli.command(name="build-bundle")
@click.option("--ojs-path", required=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Path to the OJS install.")
@click.option("--output", required=True, type=click.Path(path_type=Path),
              help="Directory to write source.tar.gz + meta.json into.")
@click.option("--category", default=None,
              help="Limit categories (comma-separated): source_code,config,upload_directory.")
@click.option("--severity", "min_severity", default="MEDIUM", show_default=True,
              help="Minimum severity recorded in meta.json scan_options.")
@click.option("--nginx-config", "nginx_config", multiple=True,
              help="Extra nginx config file or directory (repeatable).")
@click.option("--no-system-configs", is_flag=True,
              help="Do not read system web-server configs (/etc/nginx, /etc/apache2…).")
@click.option("--agent-id", default=None, help="Logical agent identifier.")
@click.option("--verbose", is_flag=True, help="Show detailed progress.")
def build_bundle_cmd(ojs_path: Path, output: Path, min_severity: str,
                     category: Optional[str], nginx_config, no_system_configs: bool,
                     agent_id: Optional[str], verbose: bool) -> None:
    """Build a bundle (source.tar.gz + meta.json) under OUTPUT without submitting."""
    _setup_logging(verbose)

    categories = _parse_csv(category)
    invalid = [c for c in categories if c not in _VALID_CATEGORIES]
    if invalid:
        click.echo(f"Error: invalid category/categories: {', '.join(invalid)}", err=True)
        sys.exit(2)

    paths = build_bundle(
        ojs_path, output,
        nginx_paths=list(nginx_config) or None,
        include_system_configs=not no_system_configs,
        categories=categories or None,
        min_severity=min_severity,
        agent_id=agent_id,
    )
    meta = paths.meta
    click.echo(f"Bundle written to {output}")
    click.echo(f"  source: {paths.source_archive} "
               f"({meta['source_archive']['bytes']} bytes, "
               f"sha256={meta['source_archive']['sha256'][:16]}…)")
    click.echo(f"  meta:   {paths.meta_json}")
    click.echo(f"  OJS version: {meta['ojs_version'] or 'unknown'} "
               f"(detected={meta['ojs_detected']})")
    click.echo(f"  config payloads: {len(meta['config_files'])}")
    click.echo(f"  upload manifest entries: {meta['upload_manifest']['total_files']}")


@cli.command(name="scan")
@click.option("--ojs-path", required=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Path to the OJS install.")
@click.option("--sast-url", required=True, help="Base URL of the OJS-SAST service.")
@click.option("--api-key-file", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=None, help="File containing the API key.")
@click.option("--api-key", default=None, help="API key (prefer --api-key-file).")
@click.option("--output-dir", type=click.Path(path_type=Path),
              default=Path("./ojs_sast_report"), show_default=True,
              help="Where to write downloaded reports.")
@click.option("--severity", "min_severity", default="MEDIUM", show_default=True)
@click.option("--format", "fmt", default="json,html,sarif", show_default=True)
@click.option("--no-system-configs", is_flag=True,
              help="Do not read system web-server configs.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification.")
@click.option("--agent-id", default=None, help="Logical agent identifier.")
@click.option("--verbose", is_flag=True, help="Show detailed progress.")
def scan_cmd(ojs_path: Path, sast_url: str, api_key_file: Optional[Path],
             api_key: Optional[str], output_dir: Path, min_severity: str, fmt: str,
             no_system_configs: bool, insecure: bool, agent_id: Optional[str],
             verbose: bool) -> None:
    """Build a bundle and submit it to a remote OJS-SAST service end-to-end."""
    _setup_logging(verbose)

    key = _load_api_key(api_key, api_key_file)
    if not key:
        click.echo("Error: provide --api-key-file or --api-key", err=True)
        sys.exit(2)

    formats = _parse_csv(fmt) or ["json"]

    # Imported here so build-bundle works without the 'agent' (httpx) extra.
    from .client import ServiceClient, ServiceError

    with tempfile.TemporaryDirectory(prefix="ojs-agent-") as tmp:
        bundle_dir = Path(tmp) / "bundle"
        paths = build_bundle(
            ojs_path, bundle_dir,
            include_system_configs=not no_system_configs,
            min_severity=min_severity, formats=formats, agent_id=agent_id,
        )
        client = ServiceClient(sast_url, key, verify=not insecure)
        try:
            submission = client.submit(paths.source_archive, paths.meta_json)
            scan_id = submission["scan_id"]
            click.echo(f"Submitted scan {scan_id} (status={submission.get('status')})")
            final = client.poll_until_finished(
                scan_id, progress=lambda m: click.echo(f"  {m}"))
            if final.get("status") != "done":
                click.echo(f"Scan {scan_id} ended as '{final.get('status')}': "
                           f"{final.get('error')}", err=True)
                sys.exit(1)
            written = client.download_reports(scan_id, output_dir, formats=formats)
            result = client.result(scan_id)
        except ServiceError as exc:
            click.echo(f"Service error: {exc}", err=True)
            sys.exit(1)

    summary = result.get("summary", {})
    click.echo(f"Scan complete: {summary.get('total_findings', 0)} finding(s)")
    by_sev = summary.get("by_severity", {})
    if by_sev:
        click.echo("  " + ", ".join(f"{k}={v}" for k, v in by_sev.items() if v))
    for fmt_name, path in written.items():
        click.echo(f"  {fmt_name.upper()} report: {path}")


if __name__ == "__main__":  # pragma: no cover
    cli()
