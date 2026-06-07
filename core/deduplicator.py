"""URL and body deduplication helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def normalize_url_for_dedup(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((scheme, netloc, path, "", query, ""))


@dataclass(slots=True)
class Deduplicator:
    seen_urls: set[str] = field(default_factory=set)
    seen_hashes: set[str] = field(default_factory=set)

    def seen_url(self, url: str) -> bool:
        normalized = normalize_url_for_dedup(url)
        if normalized in self.seen_urls:
            return True
        self.seen_urls.add(normalized)
        return False

    def seen_body_hash(self, body_hash: str) -> bool:
        if not body_hash:
            return False
        if body_hash in self.seen_hashes:
            return True
        self.seen_hashes.add(body_hash)
        return False
