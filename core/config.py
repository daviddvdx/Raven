"""Configuration loading and conservative profile handling for RAVEN."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


PROFILE_ALIASES = {
    "passive": "quiet",
    "balanced": "balanced",
    "active-safe": "balanced",
    "quiet": "quiet",
    "deep": "deep",
}


@dataclass(slots=True)
class RavenSettings:
    user_agent: str = "RAVEN/0.1.0-dev authorized-research"
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0
    retries: int = 1
    max_concurrency: int = 3
    rate_limit_per_second: float = 1.0
    follow_redirects: bool = False
    respect_robots: bool = False
    safe_mode: bool = True
    proxy: dict[str, Any] = field(default_factory=lambda: {"enabled": False, "url": ""})
    content_discovery: dict[str, Any] = field(default_factory=dict)
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def profile(self, name: str = "passive") -> dict[str, Any]:
        canonical = normalize_profile(name)
        configured = self.profiles.get(name) or self.profiles.get(canonical) or {}
        defaults = {
            "modules": ["recon"],
            "rate_limit_per_second": self.rate_limit_per_second,
            "max_concurrency": self.max_concurrency,
            "timeout": self.timeout,
            "safe_mode": True,
        }
        return {**defaults, **configured, "canonical_noise_profile": canonical}


def normalize_profile(profile: str | None) -> str:
    return PROFILE_ALIASES.get((profile or "passive").strip().lower(), "quiet")


def load_yaml(path: str | Path) -> dict[str, Any]:
    yaml_path = Path(path)
    if not yaml_path.exists():
        return {}
    return yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}


def load_settings(path: str | Path = "config/settings.yaml") -> RavenSettings:
    settings_path = Path(path)
    if not settings_path.exists():
        settings_path = Path("config/settings.example.yaml")
    data = load_yaml(settings_path)
    global_headers = dict(data.get("headers") or data.get("global_headers") or {})
    user_agent = str(data.get("user_agent") or global_headers.get("User-Agent") or "RAVEN/0.1.0-dev authorized-research")
    global_headers.setdefault("User-Agent", user_agent)
    return RavenSettings(
        user_agent=user_agent,
        headers=global_headers,
        timeout=float(data.get("timeout", 10)),
        retries=int(data.get("retries", 1)),
        max_concurrency=int(data.get("max_concurrency", data.get("threads", 3))),
        rate_limit_per_second=float(data.get("rate_limit_per_second", 1)),
        follow_redirects=bool(data.get("follow_redirects", False)),
        respect_robots=bool(data.get("respect_robots", False)),
        safe_mode=bool(data.get("safe_mode", True)),
        proxy=dict(data.get("proxy", {"enabled": False, "url": ""})),
        content_discovery=dict(data.get("content_discovery", {})),
        profiles=dict(data.get("profiles", {})),
        raw=data,
    )


def validate_settings(settings: RavenSettings) -> list[str]:
    warnings: list[str] = []
    if not settings.safe_mode:
        warnings.append("safe_mode is disabled; RAVEN should stay safe by default.")
    if settings.rate_limit_per_second > 10:
        warnings.append("rate_limit_per_second is high for default Bug Bounty reconnaissance.")
    if settings.max_concurrency > 10:
        warnings.append("max_concurrency is high; low-noise scans should keep concurrency conservative.")
    if settings.retries > 2:
        warnings.append("retries above 2 can increase noise.")
    return warnings
