"""``ojs-sast-service`` CLI — run the OJS-SAST analysis service.

``uvicorn`` and FastAPI are imported lazily inside the commands, so ``--help``
and ``gen-key`` work without the ``service`` extra.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Optional

import click

from .. import __version__
from .auth import hash_api_key


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version-flag", prog_name="ojs-sast-service")
def cli() -> None:
    """ojs-sast-service — receive scan bundles and run the analysis."""


@cli.command()
@click.option("--config", "config_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Path to service.yml.")
@click.option("--host", default=None, help="Override the configured host.")
@click.option("--port", default=None, type=int, help="Override the configured port.")
def start(config_path: Path, host: Optional[str], port: Optional[int]) -> None:
    """Start the service (FastAPI + uvicorn)."""
    from .config import ServiceConfig

    cfg = ServiceConfig.from_yaml(config_path)
    if host:
        cfg.host = host
    if port:
        cfg.port = port

    try:
        import uvicorn
    except ImportError:
        click.echo("uvicorn is required. Install with: pip install 'ojs-sast[service]'", err=True)
        sys.exit(2)

    from .app import create_app

    app = create_app(cfg)
    click.echo(f"Starting ojs-sast-service on {cfg.host}:{cfg.port} (data_dir={cfg.data_dir})")
    uvicorn.run(app, host=cfg.host, port=cfg.port)


@cli.command(name="gen-key")
@click.option("--key", default=None,
              help="Hash this key instead of generating a random one.")
def gen_key(key: Optional[str]) -> None:
    """Generate an API key and print its sha256 hash for service.yml."""
    raw = key or secrets.token_urlsafe(32)
    digest = hash_api_key(raw)
    if not key:
        click.echo(f"API key (give this to the agent): {raw}")
    click.echo(f"key_hash (put in service.yml api_keys): sha256:{digest}")


if __name__ == "__main__":  # pragma: no cover
    cli()
