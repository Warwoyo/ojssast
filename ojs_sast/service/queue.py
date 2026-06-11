"""Persistent, SQLite-backed job queue shared by all worker processes.

Unlike the original :class:`queue.Queue` wrapper (one in-memory queue per
process, lost on restart), the queue here *is* the ``scans`` table in
:class:`~ojs_sast.service.storage.Storage`:

* **enqueue** = inserting a ``queued`` row (done on the HTTP intake path via
  ``Storage.try_begin_job`` + ``Storage.mark_queued``);
* **claim** = atomically moving the oldest ``queued`` row to ``running``
  (``Storage.claim_next_job``), which is safe across processes.

This means a job submitted to one gunicorn API worker can be picked up by any
scan-worker process, the queue is shared/centralised, and jobs survive a
restart. :class:`JobQueue` is a thin coordination layer the worker pool uses to
poll for and claim work, plus a stop signal for clean shutdown.
"""

from __future__ import annotations

import threading
from typing import Optional

from .storage import Storage


class JobQueue:
    def __init__(self, storage: Storage, poll_interval: float = 0.5) -> None:
        self._storage = storage
        self.poll_interval = float(poll_interval)
        self._stop = threading.Event()

    def claim(self, worker_id: str) -> Optional[str]:
        """Atomically claim the next queued job, or ``None`` if the queue is empty."""
        return self._storage.claim_next_job(worker_id)

    def wait(self, timeout: Optional[float] = None) -> None:
        """Sleep up to ``timeout`` (default: ``poll_interval``), waking early on stop."""
        self._stop.wait(self.poll_interval if timeout is None else timeout)

    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        """Signal worker loops to exit after their current job."""
        self._stop.set()
