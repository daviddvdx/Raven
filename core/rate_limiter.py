"""Thread-safe token pacing for polite HTTP requests."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, requests_per_second: float = 2.0) -> None:
        self.requests_per_second = max(float(requests_per_second), 0.1)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        interval = 1.0 / self.requests_per_second
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                time.sleep(self._next_allowed - now)
                now = time.monotonic()
            self._next_allowed = now + interval

    def slow_down(self, factor: float = 0.5) -> None:
        self.requests_per_second = max(self.requests_per_second * factor, 0.1)
