"""Gunicorn configuration for the ojs-sast API (production).

Run::

    OJS_SAST_CONFIG=/etc/ojs-sast/service.yml \
        gunicorn -c deploy/gunicorn.conf.py ojs_sast.service.asgi:app

These gunicorn workers serve the FastAPI API only (accept uploads, enqueue
jobs). The CPU-heavy scans run in separate ``ojs-sast-service worker``
processes that drain the shared SQLite queue, so the API workers stay
I/O-bound and responsive.

Tuning reference — VPS: 4 vCPU @ ~2.4 GHz, 16 GB RAM (QEMU/KVM, Ubuntu 24.04).
Every value can be overridden via environment variables (handy for benchmarking
without editing this file).
"""

import multiprocessing
import os

# --- bind address --------------------------------------------------------- #
# Default to the host:port from service.yml so there is a single source of
# truth; override with OJS_SAST_BIND when needed.
try:
    from ojs_sast.service.config import ServiceConfig

    _cfg = ServiceConfig.from_yaml(
        os.environ.get("OJS_SAST_CONFIG", "/etc/ojs-sast/service.yml"))
    _default_bind = f"{_cfg.host}:{_cfg.port}"
except Exception:  # config not present at config-load time; fall back
    _default_bind = "0.0.0.0:8000"

bind = os.environ.get("OJS_SAST_BIND", _default_bind)

# --- workers -------------------------------------------------------------- #
# UvicornWorker is async, and scanning is offloaded to the worker pool, so the
# API is I/O-bound. ~vCPU count is plenty; bounded so a big box doesn't spawn an
# absurd number. On the 4 vCPU reference VPS this resolves to 4.
_cpus = multiprocessing.cpu_count()
workers = int(os.environ.get("GUNICORN_WORKERS", min(4, (_cpus * 2) + 1)))
worker_class = "uvicorn.workers.UvicornWorker"

# --- timeouts / recycling ------------------------------------------------- #
# Large source uploads can take a while; keep the request timeout generous.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))
graceful_timeout = int(os.environ.get("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.environ.get("GUNICORN_KEEPALIVE", "5"))
# Recycle workers periodically to bound any slow memory growth.
max_requests = int(os.environ.get("GUNICORN_MAX_REQUESTS", "1000"))
max_requests_jitter = int(os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "100"))

# --- logging -------------------------------------------------------------- #
loglevel = os.environ.get("GUNICORN_LOGLEVEL", "info")
accesslog = os.environ.get("GUNICORN_ACCESSLOG", "-")   # stdout -> journald
errorlog = os.environ.get("GUNICORN_ERRORLOG", "-")
proc_name = "ojs-sast-api"
