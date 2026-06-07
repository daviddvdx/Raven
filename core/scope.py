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
    allowed_paths: list[str] | None = None
    denied_paths: list[str] | None = None
    allowed_methods: list[str] | None = None
    max_depth: int = 2
    notes: str = ""
    bug_bounty_handle: str = ""

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        if not path:
            raise ScopeError("Un fichier de scope est obligatoire avant tout scan.")
        scope_path = Path(path)
        if not scope_path.exists():
            raise ScopeError(f"Fichier de scope introuvable: {scope_path}")
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
        allowed_domains = list(data.get("allowed_domains", data.get("in_scope_domains", [])))
        deny = list(data.get("deny", data.get("out_of_scope_domains", [])))
        denied_paths = list(data.get("denied_paths", []))
        deny.extend(denied_paths)
        return cls(
            program=str(data.get("program", data.get("program_name", "RAVEN Project"))),
            researcher=str(data.get("researcher", data.get("bug_bounty_handle", ""))),
            allowed_domains=allowed_domains,
            allowed_urls=list(data.get("allowed_urls", [])),
            deny=deny,
            rate_limit=dict(data.get("rate_limit", {"requests_per_second": 2, "burst": 3})),
            headers=dict(data.get("headers", {})),
            proxy=dict(data.get("proxy", {"enabled": False, "url": ""})),
            allowed_paths=list(data.get("allowed_paths", [])),
            denied_paths=denied_paths,
            allowed_methods=list(data.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])),
            max_depth=int(data.get("max_depth", 2)),
            notes=str(data.get("notes", "")),
            bug_bounty_handle=str(data.get("bug_bounty_handle", "")),
        )

    def validate_url(self, target: str) -> None:
        parsed = urlparse(target)
        host = parsed.hostname
        if not parsed.scheme or not host:
            raise ScopeError(f"Cible invalide: {target}")
        if self._is_denied(host, target):
            raise ScopeError(f"Cible refusee par le scope deny: {target}")
        if self.denied_paths and any(parsed.path.startswith(path) for path in self.denied_paths):
            raise ScopeError(f"Chemin refuse par le scope: {target}")
        if self.allowed_paths and not any(parsed.path.startswith(path) for path in self.allowed_paths):
            raise ScopeError(f"Chemin hors allowed_paths: {target}")
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

    def is_method_allowed(self, method: str) -> bool:
        methods = self.allowed_methods or ["GET", "HEAD", "OPTIONS"]
        return method.upper() in {item.upper() for item in methods}

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
