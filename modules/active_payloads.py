"""Safe active payload engine for authorized Bug Bounty testing."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from uuid import uuid4

from core.models import Finding, HTTPResult
from core.redaction import mask_url

REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_uri", "return", "returnurl", "continue", "callback", "destination"}
SQL_ERROR_RE = re.compile(r"(?i)(sql syntax|postgresql|mysql|mariadb|sqlite|oracle|sql server|prisma|hibernate|sequelize|typeorm)")
STACK_RE = re.compile(r"(?i)(traceback|stack trace|exception|typeerror|referenceerror|syntaxerror|at\s+[a-z0-9_.]+\()")
PATH_ERROR_RE = re.compile(r"(?i)(no such file|failed to open stream|path traversal|permission denied|root:x:)")
TEMPLATE_RE = re.compile(r"(?i)(template|jinja|twig|freemarker|velocity|handlebars|mustache)")


@dataclass(slots=True)
class PayloadEngine:
    http_client: object
    scope: object
    storage: object | None = None
    max_payloads_per_param: int = 5
    safe_mode: bool = True
    allow_post_tests: bool = False
    marker_prefix: str = "raven"
    findings: list[Finding] = field(default_factory=list)

    def scan_endpoint(self, endpoint: dict) -> list[Finding]:
        url = endpoint.get("url") or endpoint.get("endpoint")
        method = str(endpoint.get("method", "GET")).upper()
        if not url or method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            return []
        if method == "POST" and not self.allow_post_tests:
            return []
        allowed, _reason = self.scope.should_request(method, url)
        if not allowed:
            return []
        before_count = len(self.findings)
        if method == "GET":
            self._scan_query_params(url)
        elif method == "POST":
            self._scan_json_post(url)
        return self.findings[before_count:]

    def _scan_query_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return
        for name in list(params)[:20]:
            payloads = self.payloads_for_param(name)[: self.max_payloads_per_param]
            for payload in payloads:
                test_url = self._replace_param(url, name, payload)
                result = self.http_client.safe_request("GET", test_url)
                self._analyze_response(result, name, payload)

    def _scan_json_post(self, url: str) -> None:
        marker = self._marker()
        body = {"raven_marker": marker, "debug": False, "test": True}
        result = self.http_client.safe_request("POST", url, json=body, headers={"Accept": "application/json"})
        self._analyze_response(result, "json", marker)

    def payloads_for_param(self, name: str) -> list[str]:
        marker = self._marker()
        payloads = [marker, f'"><{marker}>', f'\'"><{marker}>', f'<raven-marker id="{marker}">']
        if name.lower() in REDIRECT_PARAMS:
            payloads.extend(["https://example.com/raven-redirect", "//example.com/raven-redirect", r"/\/example.com/raven-redirect"])
        if any(token in name.lower() for token in ("file", "path", "template", "page", "lang")):
            payloads.extend(["../", "../../", "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"])
        payloads.extend(["'", '"', "'--", '")--', "{{7*7}}", "${7*7}", "<%= 7*7 %>"])
        return list(dict.fromkeys(payloads))

    def _analyze_response(self, result: HTTPResult, parameter: str, payload: str) -> None:
        body = result.body_text or result.body_preview or ""
        lower_location = (result.redirect_url or "").lower()
        title = ""
        severity = "info"
        confidence = "low"
        evidence = ""
        if payload in body:
            title = "Safe reflection detected"
            severity = "low"
            confidence = "medium"
            encoded = html.escape(payload) in body and payload not in body
            evidence = f"parameter={parameter}, reflected={'encoded' if encoded else 'raw'}"
        elif result.status_code in {301, 302, 307, 308} and "example.com/raven-redirect" in lower_location:
            title = "Open redirect candidate"
            severity = "medium"
            confidence = "medium"
            evidence = f"Location={mask_url(result.redirect_url or '')}"
        elif "root:x:" in body or PATH_ERROR_RE.search(body):
            title = "Path traversal signal"
            severity = "medium" if "root:x:" in body else "low"
            confidence = "medium"
            evidence = "path traversal indicator or path error observed"
        elif SQL_ERROR_RE.search(body):
            title = "SQL error signal"
            severity = "low"
            confidence = "medium"
            evidence = "database error marker observed"
        elif "49" in body and payload in {"{{7*7}}", "${7*7}", "<%= 7*7 %>"} or TEMPLATE_RE.search(body):
            title = "Template rendering signal"
            severity = "low"
            confidence = "low"
            evidence = "template expression result or template error observed"
        elif STACK_RE.search(body):
            title = "Verbose error after safe payload"
            severity = "low"
            confidence = "medium"
            evidence = "stack trace or verbose exception observed"
        if not title:
            return
        finding = Finding(
            title=title,
            severity=severity,
            endpoint=result.url,
            description="Payload actif non destructif execute dans le scope autorise.",
            proof=f"{evidence}; payload={payload[:16]}...",
            curl_command=result.curl_command,
            impact="A confirmer manuellement; signal non destructif.",
            recommendation="Valider dans Burp Suite et corriger encodage/validation/redirect strict selon le cas.",
            score=5 if severity == "medium" else 3,
            category="active",
            confidence=confidence,
            reason=evidence,
            evidence=evidence,
            next_step="Reproduire manuellement avec un marqueur safe, sans escalade de payload.",
            tags=["active-safe", parameter],
        )
        self.findings.append(finding)
        if self.storage:
            self.storage.append_jsonl("active_findings.jsonl", finding.to_dict())

    def _replace_param(self, url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[name] = value
        return urlunparse(parsed._replace(query=urlencode(params)))

    def _marker(self) -> str:
        return f"{self.marker_prefix}-marker-{uuid4().hex[:8]}"


def run_active_payloads(context, endpoints: list[dict], payload_profile: str = "safe", max_payloads_per_param: int = 5, allow_post_tests: bool = False) -> list[Finding]:
    if payload_profile != "safe":
        raise ValueError("Only the safe payload profile is supported by default.")
    engine = PayloadEngine(
        http_client=context["http_client"],
        scope=context["scope"],
        storage=context["storage"],
        max_payloads_per_param=max_payloads_per_param,
        allow_post_tests=allow_post_tests,
    )
    findings: list[Finding] = []
    for endpoint in endpoints:
        findings.extend(engine.scan_endpoint(endpoint))
    context["storage"].save_findings(findings)
    return findings
