"""Potential public secret classification helpers."""

from __future__ import annotations

import re

from core.utils import mask_secret

SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "bearer_token": re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{16,}"),
    "basic_auth_url": re.compile(r"https?://[^/\s:@]{3,}:[^/\s:@]{3,}@"),
    "generic_secret": re.compile(r"(?i)(api[_-]?key|secret|token|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
}

ALLOWLIST = {"example", "dummy", "changeme", "placeholder", "ravenxss"}


def simple_entropy(value: str) -> float:
    if not value:
        return 0.0
    unique = len(set(value))
    return unique / max(len(value), 1)


def find_potential_secrets(text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            if any(token in value.lower() for token in ALLOWLIST):
                continue
            entropy = simple_entropy(value)
            severity = "high" if name in {"private_key", "aws_access_key_id"} else "medium" if entropy > 0.35 else "low"
            findings.append(
                {
                    "type": name,
                    "classification": "secret potentiel",
                    "severity": severity,
                    "preview": mask_secret(value),
                    "entropy": f"{entropy:.2f}",
                }
            )
    return findings
