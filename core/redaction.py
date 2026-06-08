"""Redaction helpers for logs, requests and reports."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key"}
SENSITIVE_QUERY_KEYS = {"access_token", "refresh_token", "id_token", "token", "api_key", "apikey", "key", "client_secret"}
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}")
EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]{1,3})[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def mask_secret(value: object, visible: int = 4) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    text = JWT_RE.sub(lambda match: _mask_plain(match.group(0), visible), text)
    if EMAIL_RE.fullmatch(text):
        return EMAIL_RE.sub(lambda match: f"{match.group(1)}***{match.group(2)}", text)
    text = EMAIL_RE.sub(lambda match: f"{match.group(1)}***{match.group(2)}", text)
    if len(text) <= visible * 2:
        return "*" * len(text)
    return _mask_plain(text, visible)


def _mask_plain(value: str, visible: int) -> str:
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}...{value[-visible:]}"


def mask_headers(headers: dict[str, object] | None) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if key.lower() in SENSITIVE_HEADERS:
            output[key] = mask_secret(value)
        else:
            output[key] = str(value)
    return output


def mask_url(url: str) -> str:
    parsed = urlparse(url)
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, mask_secret(value) if key.lower() in SENSITIVE_QUERY_KEYS else value))
    return urlunparse(parsed._replace(query=urlencode(query)))
