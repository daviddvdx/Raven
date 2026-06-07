"""Small low-noise task scheduler used by active modules."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from core.rate_limiter import RateLimiter


@dataclass(slots=True)
class ScheduledTask:
    name: str
    payload: Any


@dataclass(slots=True)
class LowNoiseScheduler:
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    max_tasks: int = 500
    queue: deque[ScheduledTask] = field(default_factory=deque)

    def add(self, name: str, payload: Any) -> None:
        if len(self.queue) < self.max_tasks:
            self.queue.append(ScheduledTask(name=name, payload=payload))

    def extend(self, name: str, payloads: Iterable[Any]) -> None:
        for payload in payloads:
            self.add(name, payload)

    def run(self, handler: Callable[[ScheduledTask], Any]) -> list[Any]:
        results: list[Any] = []
        while self.queue:
            self.rate_limiter.wait()
            results.append(handler(self.queue.popleft()))
        return results
