"""Agent HTTP client for submitting bundles to an OJS-SAST service.

``httpx`` is imported lazily so importing this module (and the ``ojs-agent``
CLI) never requires the optional ``agent`` extra — only constructing a
:class:`ServiceClient` does.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence

logger = logging.getLogger("ojs_sast.agent.client")

_HTTPX_HINT = (
    "The agent HTTP client requires httpx. Install it with: "
    "pip install 'ojs-sast[agent]'"
)

_TERMINAL_STATES = {"done", "error", "failed"}
_REPORT_FILENAMES = {
    "json": "ojs_sast_report.json",
    "html": "ojs_sast_report.html",
    "sarif": "ojs_sast_report.sarif",
}


def _require_httpx():
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - exercised only without httpx
        raise ImportError(_HTTPX_HINT) from exc
    return httpx


class ServiceError(RuntimeError):
    """Raised when the service returns an error or is unreachable."""


class ServiceClient:
    """Minimal client for the OJS-SAST service REST API."""

    def __init__(self, base_url: str, api_key: str, *,
                 timeout: float = 60.0, verify: bool = True, retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify = verify
        self.retries = max(1, retries)
        self._httpx = _require_httpx()

    @property
    def _headers(self) -> Dict[str, str]:
        return {"X-API-Key": self.api_key}

    def _client(self):
        return self._httpx.Client(timeout=self.timeout, verify=self.verify)

    # ----------------------------------------------------------------- #
    def submit(self, source_archive, meta_json) -> Dict[str, Any]:
        source_archive = Path(source_archive)
        meta_json = Path(meta_json)
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                with self._client() as client:
                    with source_archive.open("rb") as sf, meta_json.open("rb") as mf:
                        files = {
                            "source_code": (source_archive.name, sf, "application/gzip"),
                            "meta": (meta_json.name, mf, "application/json"),
                        }
                        resp = client.post(f"{self.base_url}/scan",
                                           headers=self._headers, files=files)
                if resp.status_code not in (200, 202):
                    raise ServiceError(
                        f"submit failed: HTTP {resp.status_code}: {resp.text[:300]}")
                return resp.json()
            except self._httpx.TransportError as exc:  # transient network error
                last_exc = exc
                if attempt < self.retries - 1:
                    time.sleep(2 ** attempt)
        raise ServiceError(f"submit failed after {self.retries} attempts: {last_exc}")

    def status(self, scan_id: str) -> Dict[str, Any]:
        with self._client() as client:
            resp = client.get(f"{self.base_url}/status/{scan_id}", headers=self._headers)
        if resp.status_code != 200:
            raise ServiceError(f"status failed: HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def poll_until_finished(self, scan_id: str, *, interval: float = 2.0,
                            max_wait: float = 600.0,
                            progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        deadline = time.time() + max_wait
        last_state = None
        while True:
            st = self.status(scan_id)
            state = st.get("status")
            if progress and state != last_state:
                progress(f"status: {state}")
            last_state = state
            if state in _TERMINAL_STATES:
                return st
            if time.time() > deadline:
                raise ServiceError(f"timed out waiting for scan {scan_id}")
            time.sleep(min(interval, max(0.0, deadline - time.time())))

    def result(self, scan_id: str) -> Dict[str, Any]:
        with self._client() as client:
            resp = client.get(f"{self.base_url}/result/{scan_id}", headers=self._headers)
        if resp.status_code != 200:
            raise ServiceError(f"result failed: HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def download_reports(self, scan_id: str, out_dir,
                         formats: Sequence[str] = ("json", "html", "sarif")) -> Dict[str, Path]:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        written: Dict[str, Path] = {}
        with self._client() as client:
            for fmt in formats:
                filename = _REPORT_FILENAMES.get(fmt)
                if not filename:
                    continue
                resp = client.get(f"{self.base_url}/report/{scan_id}/{fmt}",
                                  headers=self._headers)
                if resp.status_code == 200:
                    target = out_dir / filename
                    target.write_bytes(resp.content)
                    written[fmt] = target
                else:
                    logger.warning("report %s unavailable: HTTP %s", fmt, resp.status_code)
        return written
