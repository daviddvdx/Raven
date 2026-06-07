"""Central HTTP client based on httpx."""

from __future__ import annotations

import shlex
import json
import time
from typing import Any

import httpx

from core.models import HTTPResult
from core.rate_limiter import RateLimiter
from core.storage import Storage
from core.utils import detect_technologies, extract_title, sha256_text


class HTTPClient:
    def __init__(
        self,
        timeout: float = 10.0,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
        proxy: str | None = None,
        retries: int = 1,
        rate_limiter: RateLimiter | None = None,
        storage: Storage | None = None,
        noise_guard: Any | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.retries = max(retries, 0)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.storage = storage
        self.noise_guard = noise_guard
        self.verify_tls = verify_tls
        self._client = self._build_client()

    def _build_client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "headers": self.headers,
            "cookies": self.cookies,
            "follow_redirects": self.follow_redirects,
            "verify": self.verify_tls,
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy
        try:
            return httpx.Client(**kwargs)
        except TypeError:
            proxy = kwargs.pop("proxy", None)
            if proxy:
                kwargs["proxies"] = proxy
            return httpx.Client(**kwargs)

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, url: str, **kwargs: Any) -> HTTPResult:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            self.rate_limiter.wait()
            start = time.perf_counter()
            try:
                response = self._client.request(method.upper(), url, **kwargs)
                elapsed_ms = (time.perf_counter() - start) * 1000
                result = self._to_result(method.upper(), response, elapsed_ms, kwargs)
                if self.noise_guard:
                    self.noise_guard.observe_result(result.status_code, result.technologies)
                if self.storage and self._is_interesting(result):
                    self.storage.save_http_result("raw/http_results.jsonl", result)
                return result
            except httpx.RequestError as exc:
                last_error = exc
                if self.noise_guard:
                    self.noise_guard.observe_timeout()
                if attempt >= self.retries:
                    return self._error_result(method.upper(), url, exc)
        raise RuntimeError(f"HTTP request failed: {last_error}")

    def get(self, url: str, **kwargs: Any) -> HTTPResult:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HTTPResult:
        return self.request("POST", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> HTTPResult:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HTTPResult:
        return self.request("HEAD", url, **kwargs)

    def _to_result(self, method: str, response: httpx.Response, elapsed_ms: float, request_kwargs: dict[str, Any]) -> HTTPResult:
        text = response.text or ""
        content = response.content or b""
        headers = dict(response.headers)
        important_headers = {
            key: value
            for key, value in headers.items()
            if key.lower()
            in {
                "server",
                "location",
                "content-type",
                "content-length",
                "x-powered-by",
                "www-authenticate",
                "allow",
                "access-control-allow-origin",
                "access-control-allow-credentials",
                "access-control-allow-methods",
                "access-control-allow-headers",
                "cf-ray",
                "x-cache",
                "via",
            }
        }
        return HTTPResult(
            url=str(response.request.url),
            method=method,
            status_code=response.status_code,
            size=len(content),
            lines=text.count("\n") + (1 if text else 0),
            words=len(text.split()),
            body_hash=sha256_text(content),
            title=extract_title(text),
            important_headers=important_headers,
            redirect_url=headers.get("location"),
            response_time_ms=round(elapsed_ms, 2),
            technologies=detect_technologies(headers, text),
            curl_command=self._curl(method, str(response.request.url), request_kwargs),
            content_type=headers.get("content-type"),
            body_preview=text[:500].replace("\n", " ") if text else None,
            body_text=text,
        )

    def _curl(self, method: str, url: str, request_kwargs: dict[str, Any]) -> str:
        parts = ["curl", "-i", "-X", method]
        if not self.verify_tls:
            parts.append("-k")
        for key, value in self.headers.items():
            parts.extend(["-H", f"{key}: {value}"])
        for key, value in dict(request_kwargs.get("headers", {})).items():
            parts.extend(["-H", f"{key}: {value}"])
        data = request_kwargs.get("data") or request_kwargs.get("content")
        json_data = request_kwargs.get("json")
        if json_data is not None:
            parts.extend(["-H", "Content-Type: application/json", "--data", json.dumps(json_data)])
        elif data:
            parts.extend(["--data", str(data)])
        parts.append(url)
        return " ".join(shlex.quote(part) for part in parts)

    @staticmethod
    def _is_interesting(result: HTTPResult) -> bool:
        return result.status_code in {200, 204, 301, 302, 307, 308, 401, 403, 500, 502, 503}

    def _error_result(self, method: str, url: str, exc: Exception) -> HTTPResult:
        message = str(exc)
        return HTTPResult(
            url=url,
            method=method,
            status_code=0,
            size=0,
            lines=0,
            words=0,
            body_hash="",
            title=None,
            important_headers={"error": message[:300]},
            redirect_url=None,
            response_time_ms=0.0,
            technologies=[],
            curl_command=self._curl(method, url, {}),
            content_type=None,
            body_preview=message[:500],
            body_text="",
        )
