"""Potential public secret classification helpers."""

from __future__ import annotations

import re

SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "generic_secret": re.compile(r"(?i)(api[_-]?key|secret|token|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
}


def find_potential_secrets(text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            findings.append({"type": name, "classification": "secret potentiel", "preview": value[:12] + "***"})
    return findings
