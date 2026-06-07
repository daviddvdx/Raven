"""Adaptive noise and blocking guard for polite Bug Bounty testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


NOISE_PROFILES: dict[str, dict[str, Any]] = {
    "quiet": {
        "requests_per_second": 1,
        "threads": 1,
        "timeout": 12,
        "max_errors": 10,
        "max_403_ratio": 0.50,
        "max_429_ratio": 0.10,
        "auto_pause": True,
    },
    "balanced": {
        "requests_per_second": 2,
        "threads": 3,
        "timeout": 10,
        "max_errors": 25,
        "max_403_ratio": 0.60,
        "max_429_ratio": 0.15,
        "auto_pause": True,
    },
    "deep": {
        "requests_per_second": 5,
        "threads": 5,
        "timeout": 8,
        "max_errors": 50,
        "max_403_ratio": 0.70,
        "max_429_ratio": 0.20,
        "auto_pause": True,
    },
}

NOISE_LEVELS: dict[int, dict[str, Any]] = {
    1: {"label": "passive only", "allow_fuzz": False, "allow_post": False, "rate_per_minute": 2, "rate": 0.03, "threads": 1, "requires_strong_confirmation": False},
    2: {"label": "light JS", "allow_fuzz": True, "allow_post": False, "rate": 2, "threads": 1, "wordlist": "small", "requires_strong_confirmation": False},
    3: {"label": "light content discovery", "allow_fuzz": True, "allow_post": False, "rate": 5, "threads": 3, "wordlist": "common", "requires_strong_confirmation": False},
    4: {"label": "balanced discovery", "allow_fuzz": True, "allow_post": False, "rate": 8, "threads": 4, "requires_strong_confirmation": False},
    5: {"label": "balanced API checks", "allow_fuzz": True, "allow_post": False, "rate": 10, "threads": 5, "requires_strong_confirmation": False},
    6: {"label": "balanced plus", "allow_fuzz": True, "allow_post": False, "rate": 10, "threads": 5, "requires_strong_confirmation": False},
    7: {"label": "deeper wordlists", "allow_fuzz": True, "allow_post": False, "rate": 15, "threads": 7, "requires_strong_confirmation": True},
    8: {"label": "deep confirmed", "allow_fuzz": True, "allow_post": False, "rate": 20, "threads": 8, "requires_strong_confirmation": True},
    9: {"label": "aggressive", "allow_fuzz": True, "allow_post": False, "rate": 20, "threads": 10, "requires_strong_confirmation": True},
    10: {"label": "aggressive maximum", "allow_fuzz": True, "allow_post": False, "rate": 20, "threads": 10, "requires_strong_confirmation": True},
}


def get_noise_profile(name: str | None = None) -> dict[str, Any]:
    return dict(NOISE_PROFILES.get(name or "quiet", NOISE_PROFILES["quiet"]))


def noise_level_config(level: int) -> dict[str, Any]:
    level = max(1, min(int(level), 10))
    return dict(NOISE_LEVELS[level])


def requires_strong_confirmation_for_noise(level: int) -> bool:
    return bool(noise_level_config(level).get("requires_strong_confirmation"))


def is_noise_allowed_for_yes(level: int) -> bool:
    return int(level) < 9


@dataclass(slots=True)
class NoiseGuard:
    profile_name: str = "quiet"
    logger: Any | None = None
    total: int = 0
    status_403: int = 0
    status_429: int = 0
    status_503: int = 0
    timeouts: int = 0
    errors: int = 0
    paused: bool = False
    messages: list[str] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.profile = get_noise_profile(self.profile_name)

    def observe_result(self, status_code: int, technologies: list[str] | None = None) -> None:
        self.total += 1
        if status_code == 403:
            self.status_403 += 1
        elif status_code == 429:
            self.status_429 += 1
        elif status_code == 503:
            self.status_503 += 1
        if status_code in {429, 503} or self._ratio(self.status_429) > self.profile["max_429_ratio"]:
            self._react("Possible rate limit or WAF/CDN reaction detected; slowing down and keeping the run non-bypass.")
        if self._ratio(self.status_403) > self.profile["max_403_ratio"] and self.total >= 5:
            self._react("High 403 ratio detected; reducing request pressure.")
        if technologies and any(item.lower() in {"cloudflare", "akamai", "datadome", "cloudfront", "fastly"} for item in technologies):
            self._log("WAF/CDN signal observed; RAVEN will not attempt bypass behavior.")

    def observe_timeout(self) -> None:
        self.total += 1
        self.timeouts += 1
        self.errors += 1
        if self.errors >= self.profile["max_errors"]:
            self._react("Too many errors/timeouts; pausing noisy behavior for manual review.")

    def should_pause(self) -> bool:
        return bool(self.paused and self.profile.get("auto_pause", True))

    def summary(self) -> dict[str, Any]:
        return {
            "profile": self.profile_name,
            "total": self.total,
            "403": self.status_403,
            "429": self.status_429,
            "503": self.status_503,
            "timeouts": self.timeouts,
            "errors": self.errors,
            "paused": self.paused,
            "messages": self.messages,
        }

    def _ratio(self, value: int) -> float:
        return value / self.total if self.total else 0.0

    def _react(self, message: str) -> None:
        self.paused = True
        self._log(message)

    def _log(self, message: str) -> None:
        if message not in self.messages:
            self.messages.append(message)
        if self.logger:
            self.logger.warning(message)
