"""Lightweight progress reporting.

Members are streamed through the queue, so we want to print as each finishes
(not wait for the whole pool). cli.py already prints phase headers; this
module just provides a thread-safe per-event sink the member orchestrator
can call.
"""

from __future__ import annotations

import sys
import threading
import time


class ProgressReporter:
    def __init__(self, verbose: bool = False, stream=None) -> None:
        self.verbose = verbose
        self.stream = stream or sys.stdout
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {
            "submitted": 0,
            "success": 0,
            "partial": 0,
            "failed": 0,
        }
        self.start_time = time.time()

    def member_event(self, event: str, account_id: str) -> None:
        with self._lock:
            self._counts[event] = self._counts.get(event, 0) + 1
            line = (
                f"  [member] {event:<9s} {account_id}  "
                f"(submitted={self._counts['submitted']} "
                f"success={self._counts['success']} "
                f"partial={self._counts['partial']} "
                f"failed={self._counts['failed']})"
            )
            print(line, file=self.stream, flush=True)

    @property
    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def elapsed(self) -> float:
        return time.time() - self.start_time
