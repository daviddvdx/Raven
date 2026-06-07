"""Polite crawler for authorized targets."""

from __future__ import annotations

from collections import deque
from urllib.parse import urldefrag, urlparse

from bs4 import BeautifulSoup

from core.models import Finding
from core.utils import resolve_url


def crawl(context, depth: int = 2, max_pages: int = 100) -> dict[str, list[str]]:
    scope = context["scope"]
    storage = context["storage"]
    http_client = context["http_client"]
    start_url = context["target"]
    seen: set[str] = set()
    urls: set[str] = set()
    js_files: set[str] = set()
    forms: list[str] = []
    queue = deque([(start_url, 0)])

    while queue and len(seen) < max_pages:
        url, current_depth = queue.popleft()
        normalized = urldefrag(url)[0].rstrip("/")
        if normalized in seen or not scope.is_allowed_url(normalized):
            continue
        seen.add(normalized)
        try:
            result = http_client.get(normalized)
        except Exception:
            continue
        storage.append_line("urls.txt", result.url)
        urls.add(result.url)
        if "text/html" not in (result.content_type or ""):
            continue
        soup = BeautifulSoup(result.body_text or "", "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action") or normalized
            forms.append(resolve_url(normalized, action))
        for script in soup.find_all("script", src=True):
            js_url = resolve_url(normalized, script["src"])
            if scope.is_allowed_url(js_url):
                js_files.add(js_url)
                storage.append_line("js_files.txt", js_url)
        if current_depth >= depth:
            continue
        for tag in soup.find_all(["a", "link"], href=True):
            href = resolve_url(normalized, tag["href"])
            href = urldefrag(href)[0]
            if scope.is_allowed_url(href) and urlparse(href).scheme in {"http", "https"}:
                queue.append((href, current_depth + 1))

    storage.write_json(
        "crawler_results.json",
        {"urls": sorted(urls), "js_files": sorted(js_files), "forms": sorted(set(forms))},
    )
    return {"urls": sorted(urls), "js_files": sorted(js_files), "forms": sorted(set(forms))}


def run_crawler(context, depth: int = 2) -> list[Finding]:
    data = crawl(context, depth=depth)
    findings = [
        Finding(
            title="Crawl termine",
            severity="informational",
            endpoint=context["target"],
            description="URLs, formulaires et fichiers JavaScript visibles ont ete collectes.",
            proof=f"{len(data['urls'])} URL(s), {len(data['js_files'])} JS, {len(data['forms'])} formulaire(s)",
            score=1,
            tags=["crawl"],
        )
    ]
    context["storage"].save_findings(findings)
    return findings
