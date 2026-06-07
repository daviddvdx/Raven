"""SecLists detection and conservative wordlist profile selection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_SECLISTS_PATHS = [
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
    "/opt/SecLists",
]

DEFAULT_PROFILES: dict[str, dict[str, list[str]]] = {
    "quiet": {
        "web_content": ["Discovery/Web-Content/common.txt", "Discovery/Web-Content/raft-small-words.txt"],
        "api": ["Discovery/Web-Content/api/api-endpoints.txt", "Discovery/Web-Content/raft-small-words.txt"],
        "sensitive": ["Discovery/Web-Content/quickhits.txt", "Discovery/Web-Content/common.txt"],
    },
    "balanced": {
        "web_content": [
            "Discovery/Web-Content/common.txt",
            "Discovery/Web-Content/raft-medium-words.txt",
            "Discovery/Web-Content/directory-list-2.3-small.txt",
        ],
        "api": ["Discovery/Web-Content/api/api-endpoints.txt", "Discovery/Web-Content/raft-medium-words.txt"],
    },
    "deep": {
        "web_content": ["Discovery/Web-Content/raft-large-words.txt", "Discovery/Web-Content/directory-list-2.3-medium.txt"],
        "api": ["Discovery/Web-Content/api/api-endpoints.txt", "Discovery/Web-Content/raft-large-words.txt"],
    },
}


@dataclass(slots=True)
class WordlistStatus:
    seclists_detected: bool
    base_path: str | None
    profiles: dict[str, dict[str, list[str]]]
    existing: list[str]
    missing: list[str]
    selected: list[str]
    fallback: list[str]


class WordlistManager:
    def __init__(self, settings_path: str | Path = "config/settings.yaml") -> None:
        self.settings = self._load_settings(settings_path)
        self.base_paths = self._base_paths()
        self.profiles = self.settings.get("wordlist_profiles") or DEFAULT_PROFILES
        self.base_path = self.detect_seclists()

    def detect_seclists(self) -> Path | None:
        for candidate in self.base_paths:
            path = Path(candidate)
            if path.exists() and path.is_dir():
                return path
        return None

    def status(self, profile: str = "quiet", mode: str = "web_content") -> WordlistStatus:
        selected = self.select_wordlists(profile, mode)
        existing, missing = self.check_wordlists(profile, mode)
        return WordlistStatus(
            seclists_detected=self.base_path is not None,
            base_path=str(self.base_path) if self.base_path else None,
            profiles=self.profiles,
            existing=[str(item) for item in existing],
            missing=missing,
            selected=[str(item) for item in selected],
            fallback=self.fallback_wordlists(mode),
        )

    def select_wordlists(self, profile: str = "quiet", mode: str = "web_content", allow_deep: bool = False) -> list[Path]:
        if profile == "deep" and not allow_deep:
            profile = "quiet"
        existing, _missing = self.check_wordlists(profile, mode)
        if existing:
            return existing
        return [Path(item) for item in self.fallback_wordlists(mode)]

    def check_wordlists(self, profile: str = "quiet", mode: str = "web_content") -> tuple[list[Path], list[str]]:
        entries = self.profiles.get(profile, self.profiles["quiet"]).get(mode, [])
        existing: list[Path] = []
        missing: list[str] = []
        for entry in entries:
            path = self.resolve(entry)
            if path and path.exists():
                existing.append(path)
            else:
                missing.append(entry)
        return existing, missing

    def resolve(self, relative_or_absolute: str) -> Path | None:
        path = Path(relative_or_absolute)
        if path.is_absolute():
            return path
        if self.base_path:
            return self.base_path / relative_or_absolute
        return None

    def fallback_wordlists(self, mode: str = "web_content") -> list[str]:
        if mode == "api":
            return ["wordlists/api.txt"]
        return ["wordlists/small.txt"]

    def _base_paths(self) -> list[str]:
        configured = self.settings.get("seclists", {}).get("base_paths", [])
        return list(dict.fromkeys([*configured, *DEFAULT_SECLISTS_PATHS]))

    @staticmethod
    def _load_settings(settings_path: str | Path) -> dict[str, Any]:
        path = Path(settings_path)
        if not path.exists():
            path = Path("config/settings.example.yaml")
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
