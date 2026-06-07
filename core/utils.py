"""Small helpers used across RAVEN modules."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


def sha256_text(value: str | bytes) -> str:
    data = value.encode("utf-8", errors="ignore") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def extract_title(html: str) -> str | None:
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    title = soup.find("title")
    if not title or not title.text:
        return None
    return " ".join(title.text.split())[:180]


def detect_technologies(headers: dict[str, str], body: str = "") -> list[str]:
    found: set[str] = set()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    server = lower_headers.get("server", "")
    powered_by = lower_headers.get("x-powered-by", "")
    marker_text = f"{server} {powered_by} {body[:4000].lower()}"
    markers = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "fastly": "Fastly",
        "cloudfront": "CloudFront",
        "nginx": "nginx",
        "apache": "Apache",
        "express": "Express",
        "next.js": "Next.js",
        "react": "React",
        "vue": "Vue",
        "wordpress": "WordPress",
        "django": "Django",
        "laravel": "Laravel",
        "angular": "Angular",
        "nuxt": "Nuxt",
        "vite": "Vite",
        "webpack": "Webpack",
        "keycloak": "Keycloak",
        "amazon api gateway": "API Gateway",
        "x-amzn-requestid": "API Gateway",
        "istio": "Istio",
        "envoy": "Envoy",
    }
    for marker, label in markers.items():
        if marker in marker_text:
            found.add(label)
    if "cf-ray" in lower_headers:
        found.add("Cloudflare")
    if "x-cache" in lower_headers:
        found.add("Cache")
    return sorted(found)


def mask_secret(value: str, visible: int = 4) -> str:
    if not value:
        return ""
    compact = str(value)
    if len(compact) <= visible * 2:
        return "*" * len(compact)
    return f"{compact[:visible]}...{compact[-visible:]}"


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_int_csv(value: str | None) -> set[int]:
    output: set[int] = set()
    for item in parse_csv(value):
        try:
            output.add(int(item))
        except ValueError:
            continue
    return output


def normalize_extension(value: str) -> str:
    clean = value.strip()
    if not clean:
        return clean
    return clean if clean.startswith(".") else f".{clean}"


def slugify(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return clean or "default"


def project_from_target(target: str) -> str:
    parsed = urlparse(target)
    return slugify(parsed.netloc or parsed.path or "default")


def resolve_url(base: str, href: str) -> str:
    return urljoin(base, href)


def read_wordlist(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
