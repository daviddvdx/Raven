"""WAF/CDN signal detector without bypass logic."""

from __future__ import annotations


def detect_waf(headers: dict[str, str], body_preview: str | None = None, status_code: int | None = None) -> list[str]:
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    text = " ".join(lower.values()) + " " + (body_preview or "").lower()
    found: set[str] = set()
    if "cf-ray" in lower or "cloudflare" in text:
        found.add("Cloudflare")
    if "datadome" in text:
        found.add("DataDome")
    if "akamai" in text:
        found.add("Akamai")
    if "awselb" in text or "aws" in text and status_code in {403, 429, 503}:
        found.add("AWS WAF")
    if "mod_security" in text or "modsecurity" in text:
        found.add("ModSecurity")
    if "fastly" in text:
        found.add("Fastly")
    if "cloudfront" in text:
        found.add("CloudFront")
    if "nginx" in text:
        found.add("nginx")
    return sorted(found)
