"""ASGI entrypoint for running the service under Gunicorn (production).

Gunicorn imports a module-level ASGI app; it has no idea where ``service.yml``
lives. This thin layer bridges that gap: it reads the config path from the
environment, loads :class:`ServiceConfig`, and calls
:func:`ojs_sast.service.app.create_app`.

    CLI (dev)  : read config -> create_app(config) -> uvicorn.run(app)
    Gunicorn   : import this -> read config from env -> create_app(config)

Usage::

    OJS_SAST_CONFIG=/etc/ojs-sast/service.yml \
        gunicorn -c deploy/gunicorn.conf.py ojs_sast.service.asgi:app

By default the gunicorn workers are **API-only** (``run_worker=False``): they
accept uploads and enqueue jobs into the shared, persistent SQLite queue, while
the scans run in separate ``ojs-sast-service worker`` processes. Set
``OJS_SAST_EMBED_WORKER=1`` to also run the worker pool inside each gunicorn
worker (only sensible for a single-worker deployment).

Environment variables:

* ``OJS_SAST_CONFIG`` — path to ``service.yml`` (default ``/etc/ojs-sast/service.yml``).
* ``OJS_SAST_EMBED_WORKER`` — ``1``/``true`` to embed the worker pool (default off).
"""

from __future__ import annotations

import os

from .app import create_app
from .config import ServiceConfig

DEFAULT_CONFIG_PATH = "/etc/ojs-sast/service.yml"


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def build_app(config_path: "str | None" = None, *, run_worker: "bool | None" = None):
    """Build the FastAPI app from the configured ``service.yml``.

    Both arguments fall back to environment variables, so Gunicorn can simply
    import the module-level :data:`app`.
    """
    path = config_path or os.environ.get("OJS_SAST_CONFIG", DEFAULT_CONFIG_PATH)
    cfg = ServiceConfig.from_yaml(path)
    embed = run_worker if run_worker is not None else _truthy(
        os.environ.get("OJS_SAST_EMBED_WORKER", "0"))
    return create_app(cfg, run_worker=embed)


# Gunicorn target: ``ojs_sast.service.asgi:app``.
app = build_app()
