import hashlib

import pytest

from core.models import HTTPResult
from core.scope import Scope
from core.storage import Storage


def make_http_result(
    url: str,
    status_code: int = 200,
    body: str = "ok",
    content_type: str = "text/html",
    technologies: list[str] | None = None,
) -> HTTPResult:
    lines = body.count("\n") + 1 if body else 0
    words = len(body.split())
    return HTTPResult(
        url=url,
        method="GET",
        status_code=status_code,
        size=len(body.encode("utf-8")),
        lines=lines,
        words=words,
        body_hash=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        title=None,
        important_headers={"content-type": content_type},
        redirect_url=None,
        response_time_ms=12,
        technologies=technologies or [],
        curl_command=f"curl -i {url}",
        content_type=content_type,
        body_preview=body[:120],
        body_text=body,
    )


class StaticHTTPClient:
    def __init__(self, routes: dict[str, HTTPResult] | None = None, default: HTTPResult | None = None) -> None:
        self.routes = routes or {}
        self.default = default
        self.calls: list[dict] = []

    def get(self, url: str, headers: dict[str, str] | None = None) -> HTTPResult:
        self.calls.append({"url": url, "headers": headers or {}})
        if url in self.routes:
            return self.routes[url]
        if self.default:
            return self.default
        return make_http_result(url, 404, "not found")


@pytest.fixture
def allowed_scope() -> Scope:
    return Scope(
        program="Tests",
        researcher="pytest",
        allowed_domains=["example.com"],
        allowed_urls=["https://example.com"],
        deny=[],
        rate_limit={"requests_per_second": 10},
        headers={},
        proxy={"enabled": False, "url": ""},
    )


@pytest.fixture
def context_factory(tmp_path, allowed_scope):
    def build(target: str = "https://example.com/FUZZ", http_client: StaticHTTPClient | None = None):
        return {
            "project": "pytest-project",
            "target": target,
            "scope": allowed_scope,
            "storage": Storage("pytest-project", base_dir=tmp_path),
            "http_client": http_client or StaticHTTPClient(),
            "profile": "quiet",
            "threads": 1,
        }

    return build
