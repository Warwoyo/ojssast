"""FastAPI application factory for the OJS-SAST service.

FastAPI is imported (guarded) at module level so endpoint type annotations like
``UploadFile`` resolve correctly. Nothing on the core CLI / ``scan-bundle`` path
imports this module, and the ``ojs-sast-service`` CLI imports it lazily, so a
bare install (without the ``service`` extra) is unaffected.
"""

import hashlib
import json
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from .. import __version__
from ..ruleset.loader import load_ruleset
from .auth import api_key_id, ip_allowed, verify_api_key, write_audit
from .config import ServiceConfig
from .queue import JobQueue
from .storage import Storage
from .worker import Worker

logger = logging.getLogger("ojs_sast.service.app")

_SERVICE_HINT = (
    "FastAPI is required to run the service. Install it with: "
    "pip install 'ojs-sast[service]'"
)

try:
    from fastapi import (FastAPI, File, Header, HTTPException, Request,
                         UploadFile)
    from fastapi.responses import FileResponse, JSONResponse
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the service extra
    _FASTAPI_AVAILABLE = False

_REPORT_COLUMN = {
    "json": "report_json_path",
    "html": "report_html_path",
    "sarif": "report_sarif_path",
}
_REPORT_MEDIA = {
    "json": "application/json",
    "html": "text/html",
    "sarif": "application/json",
}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_app(config: ServiceConfig):
    if not _FASTAPI_AVAILABLE:
        raise ImportError(_SERVICE_HINT)

    storage = Storage(config.data_dir)
    job_queue = JobQueue()
    ruleset = load_ruleset()
    worker = Worker(storage, job_queue, config, ruleset=ruleset)

    @asynccontextmanager
    async def lifespan(_app):
        worker.start()
        try:
            yield
        finally:
            worker.stop()

    app = FastAPI(title="ojs-sast-service", version=__version__, lifespan=lifespan)
    app.state.config = config
    app.state.storage = storage
    app.state.queue = job_queue
    app.state.worker = worker

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else ""

    def _require_auth(request: Request, x_api_key: Optional[str]) -> str:
        agent = verify_api_key(x_api_key or "", config.api_keys)
        if not agent:
            raise HTTPException(status_code=401, detail="invalid or missing API key")
        if not ip_allowed(_client_ip(request), config.ip_allowlist):
            raise HTTPException(status_code=403, detail="client IP not allowed")
        return agent

    async def _save_upload(upload: UploadFile, dest: Path, max_bytes: int) -> int:
        size = 0
        with dest.open("wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail="source archive too large")
                out.write(chunk)
        return size

    # ------------------------------------------------------------------ #
    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/scan")
    async def scan(request: Request,
                   source_code: UploadFile = File(...),
                   meta: UploadFile = File(...),
                   x_api_key: Optional[str] = Header(default=None)):
        _require_auth(request, x_api_key)
        kid = api_key_id(x_api_key)

        if storage.count_active(kid) >= config.max_active_scans_per_key:
            raise HTTPException(status_code=429, detail="too many active scans for this key")

        scan_id = str(uuid.uuid4())
        job_dir = storage.create_job(scan_id, kid)
        source_path = job_dir / "source.tar.gz"
        meta_path = job_dir / "meta.json"

        try:
            size = await _save_upload(source_code, source_path, config.max_upload_bytes)
            meta_bytes = await meta.read()
            if len(meta_bytes) > config.max_upload_bytes:
                raise HTTPException(status_code=413, detail="meta.json too large")
            meta_path.write_bytes(meta_bytes)
            try:
                meta_obj = json.loads(meta_bytes)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="invalid meta.json") from exc

            expected = (meta_obj.get("source_archive") or {}).get("sha256")
            if expected and _sha256_file(source_path) != expected:
                raise HTTPException(status_code=400, detail="source archive sha256 mismatch")
        except HTTPException:
            storage.update(scan_id, status="error", error="rejected at intake")
            raise

        storage.update(scan_id, status="queued",
                       source_sha256=expected, source_bytes=size)
        job_queue.put(scan_id)
        write_audit(config.audit_log_path,
                    {"scan_id": scan_id, "status": "queued",
                     "api_key_id": kid, "ip": _client_ip(request),
                     "source_bytes": size})
        return JSONResponse(status_code=202,
                            content={"scan_id": scan_id, "status": "queued"})

    @app.get("/status/{scan_id}")
    def status(request: Request, scan_id: str, x_api_key: Optional[str] = Header(default=None)):
        _require_auth(request, x_api_key)
        view = storage.status_view(scan_id)
        if view is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        return view

    @app.get("/result/{scan_id}")
    def result(request: Request, scan_id: str, x_api_key: Optional[str] = Header(default=None)):
        _require_auth(request, x_api_key)
        row = storage.get(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        if row["status"] != "done":
            raise HTTPException(status_code=409,
                                detail=f"scan not finished (status={row['status']})")
        result_path = row.get("result_path") or str(storage.job_dir(scan_id) / "result.json")
        if not Path(result_path).is_file():
            raise HTTPException(status_code=404, detail="result not available")
        return JSONResponse(content=json.loads(Path(result_path).read_text(encoding="utf-8")))

    @app.get("/report/{scan_id}/{fmt}")
    def report(request: Request, scan_id: str, fmt: str,
               x_api_key: Optional[str] = Header(default=None)):
        _require_auth(request, x_api_key)
        if fmt not in _REPORT_COLUMN:
            raise HTTPException(status_code=400, detail="format must be json|html|sarif")
        row = storage.get(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="unknown scan_id")
        if row["status"] != "done":
            raise HTTPException(status_code=409,
                                detail=f"scan not finished (status={row['status']})")
        path = row.get(_REPORT_COLUMN[fmt])
        if not path or not Path(path).is_file():
            raise HTTPException(status_code=404, detail="report not available")
        return FileResponse(path, media_type=_REPORT_MEDIA[fmt], filename=Path(path).name)

    return app
