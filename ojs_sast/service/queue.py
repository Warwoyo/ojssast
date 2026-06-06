"""A minimal in-process job queue for the MVP service.

Thin wrapper over :class:`queue.Queue`. ``None`` is reserved as the shutdown
sentinel so the worker thread can be stopped cleanly.
"""

from __future__ import annotations

import queue
from typing import Optional


class JobQueue:
    SENTINEL = None

    def __init__(self) -> None:
        self._q: "queue.Queue[Optional[str]]" = queue.Queue()

    def put(self, scan_id: Optional[str]) -> None:
        self._q.put(scan_id)

    def get(self, timeout: Optional[float] = None) -> Optional[str]:
        return self._q.get(timeout=timeout)

    def task_done(self) -> None:
        self._q.task_done()

    def stop(self) -> None:
        """Enqueue the shutdown sentinel."""
        self._q.put(self.SENTINEL)
