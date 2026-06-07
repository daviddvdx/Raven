"""Standard result models kept compatible with the original RAVEN models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.models import Finding, HTTPResult


@dataclass(slots=True)
class Endpoint:
    url: str
    endpoint_type: str = "unknown"
    source: str = "observed"
    method: str = "GET"
    depth: int = 0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "type": self.endpoint_type,
            "source": self.source,
            "method": self.method,
            "depth": self.depth,
            "tags": self.tags,
        }


RequestResult = HTTPResult

__all__ = ["Endpoint", "Finding", "RequestResult"]
