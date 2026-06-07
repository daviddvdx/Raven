"""Shared data models for RAVEN."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class HTTPResult:
    url: str
    method: str
    status_code: int
    size: int
    lines: int
    words: int
    body_hash: str
    title: str | None
    important_headers: dict[str, str]
    redirect_url: str | None
    response_time_ms: float
    technologies: list[str]
    curl_command: str
    content_type: str | None = None
    body_preview: str | None = None
    body_text: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("body_text", None)
        return data


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    endpoint: str
    description: str
    proof: str
    curl_command: str = ""
    impact: str = "A verifier manuellement."
    recommendation: str = "Valider dans le cadre du programme Bug Bounty autorise."
    status: str = "a verifier"
    score: int = 0
    category: str = "endpoint"
    confidence: str = "low"
    reason: str = ""
    evidence: str = ""
    next_step: str = "Verifier manuellement dans Burp Suite."
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
