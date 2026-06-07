"""Scope validation for authorized Bug Bounty testing."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeError(ValueError):
    pass


@dataclass(slots=True)
class Scope:
    program: str
    researcher: str
    allowed_domains: list[str]
    allowed_urls: list[str]
    deny: list[str]
    rate_limit: dict
    headers: dict[str, str]
    proxy: dict

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        if not path:
            raise ScopeError("Un fichier de scope est obligatoire avant tout scan.")
        scope_path = Path(path)
        if not scope_path.exists():
            raise ScopeError(f"Fichier de scope introuvable: {scope_path}")
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
        return cls(
            program=str(data.get("program", "RAVEN Project")),
            researcher=str(data.get("researcher", "")),
            allowed_domains=list(data.get("allowed_domains", [])),
            allowed_urls=list(data.get("allowed_urls", [])),
            deny=list(data.get("deny", [])),
            rate_limit=dict(data.get("rate_limit", {"requests_per_second": 2, "burst": 3})),
            headers=dict(data.get("headers", {})),
            proxy=dict(data.get("proxy", {"enabled": False, "url": ""})),
        )

    def validate_url(self, target: str) -> None:
        parsed = urlparse(target)
        host = parsed.hostname
        if not parsed.scheme or not host:
            raise ScopeError(f"Cible invalide: {target}")
        if self._is_denied(host, target):
            raise ScopeError(f"Cible refusee par le scope deny: {target}")
        if self._is_private_ip(host) and host not in self.allowed_domains:
            raise ScopeError(f"IP privee bloquee car non explicitement autorisee: {host}")
        if self._url_allowed(target) or self._domain_allowed(host):
            return
        raise ScopeError(f"Cible hors scope: {target}")

    def is_allowed_url(self, target: str) -> bool:
        try:
            self.validate_url(target)
            return True
        except ScopeError:
            return False

    def requests_per_second(self, default: float = 2.0) -> float:
        try:
            return float(self.rate_limit.get("requests_per_second", default))
        except (TypeError, ValueError):
            return default

    def _url_allowed(self, target: str) -> bool:
        normalized = target.rstrip("/")
        return any(normalized.startswith(url.rstrip("/")) for url in self.allowed_urls)

    def _domain_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for pattern in self.allowed_domains:
            candidate = pattern.lower().rstrip(".")
            if candidate.startswith("*."):
                suffix = candidate[2:]
                if host.endswith(f".{suffix}") and host != suffix:
                    return True
            elif host == candidate:
                return True
        return False

    def _is_denied(self, host: str, target: str) -> bool:
        host = host.lower().rstrip(".")
        target = target.lower()
        for item in self.deny:
            candidate = str(item).lower().rstrip("/")
            if host == candidate or target.startswith(candidate):
                return True
        return False

    @staticmethod
    def _is_private_ip(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
