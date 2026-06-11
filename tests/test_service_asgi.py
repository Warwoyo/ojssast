"""Tests for the Gunicorn ASGI entrypoint (ojs_sast.service.asgi).

Verifies it loads config from the environment and builds the FastAPI app, and
that gunicorn workers are API-only by default (no embedded scan worker) but can
opt in via OJS_SAST_EMBED_WORKER.
"""

from __future__ import annotations

import importlib

import pytest

pytest.importorskip("fastapi")


def _write_cfg(tmp_path):
    cfg = tmp_path / "service.yml"
    cfg.write_text(
        f'data_dir: "{tmp_path / "svc"}"\napi_keys: []\n', encoding="utf-8")
    return cfg


def test_asgi_builds_api_only_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("OJS_SAST_CONFIG", str(_write_cfg(tmp_path)))
    monkeypatch.delenv("OJS_SAST_EMBED_WORKER", raising=False)

    import ojs_sast.service.asgi as asgi
    importlib.reload(asgi)

    assert asgi.app is not None
    assert asgi.app.title == "ojs-sast-service"
    # Gunicorn API workers must not run the scan-worker pool.
    assert asgi.app.state.worker is None
    # ...but the shared persistent queue is wired up for enqueueing.
    assert asgi.app.state.queue is not None


def test_asgi_can_embed_worker_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OJS_SAST_CONFIG", str(_write_cfg(tmp_path)))
    monkeypatch.setenv("OJS_SAST_EMBED_WORKER", "1")

    import ojs_sast.service.asgi as asgi
    importlib.reload(asgi)

    assert asgi.app.state.worker is not None


def test_build_app_run_worker_argument_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("OJS_SAST_CONFIG", str(_write_cfg(tmp_path)))
    import ojs_sast.service.asgi as asgi
    importlib.reload(asgi)

    api_only = asgi.build_app(str(_write_cfg(tmp_path)), run_worker=False)
    embedded = asgi.build_app(str(_write_cfg(tmp_path)), run_worker=True)
    assert api_only.state.worker is None
    assert embedded.state.worker is not None
