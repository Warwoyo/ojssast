"""``ojs-sast-service`` CLI — run the OJS-SAST analysis service.

Two deployment modes:

* **Development / all-in-one** — ``ojs-sast-service start`` runs FastAPI under
  uvicorn in one process, with the scan-worker pool embedded. Simple, no extra
  moving parts; ideal for local testing.
* **Production** — gunicorn (process manager) serves the API via the ASGI
  entrypoint ``ojs_sast.service.asgi:app``, and one or more
  ``ojs-sast-service worker`` processes drain the shared persistent queue.
  Both are normally managed by systemd (see ``deploy/``).

``uvicorn`` and FastAPI are imported lazily inside the commands, so ``--help``
and ``gen-key`` work without the ``service`` extra.
"""

from __future__ import annotations

import secrets
import sys
import time
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
    """Start the all-in-one dev server (FastAPI + uvicorn + embedded worker).

    For production use gunicorn + a separate ``worker`` process instead; see the
    deployment docs and ``deploy/``.
    """
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

    app = create_app(cfg)  # run_worker=True: embed the scan-worker pool
    click.echo(f"Starting ojs-sast-service (dev) on {cfg.host}:{cfg.port} "
               f"(data_dir={cfg.data_dir})")
    uvicorn.run(app, host=cfg.host, port=cfg.port)


@cli.command()
@click.option("--config", "config_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Path to service.yml.")
@click.option("--concurrency", default=None, type=int,
              help="Worker threads in this process (default: worker_concurrency "
                   "from config). Prefer scaling processes for CPU-bound scans.")
def worker(config_path: Path, concurrency: Optional[int]) -> None:
    """Run a scan-worker process that drains the shared persistent queue.

    Production runs one or more of these alongside the gunicorn API (e.g. a
    systemd template ``ojs-sast-worker@1..N``). Each process claims jobs
    atomically from the SQLite-backed queue, so they never double-run a scan,
    and recovers jobs orphaned by a crashed worker on start-up.
    """
    import signal

    from ..ruleset.loader import load_ruleset
    from .config import ServiceConfig
    from .queue import JobQueue
    from .storage import Storage
    from .worker import Worker

    cfg = ServiceConfig.from_yaml(config_path)
    storage = Storage(cfg.data_dir)
    job_queue = JobQueue(storage, poll_interval=cfg.poll_interval_seconds)
    pool = Worker(storage, job_queue, cfg, ruleset=load_ruleset(),
                  concurrency=concurrency or cfg.worker_concurrency)

    def _shutdown(_signum, _frame):
        job_queue.stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    click.echo(f"Starting ojs-sast worker (concurrency={pool.concurrency}, "
               f"id={pool.worker_id}, data_dir={cfg.data_dir})")
    pool.start()
    try:
        while not job_queue.stopped():
            time.sleep(0.5)
    finally:
        pool.stop()
    click.echo("ojs-sast worker stopped")


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
