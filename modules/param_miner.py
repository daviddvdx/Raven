"""Low-noise hidden parameter miner."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from uuid import uuid4

from core.models import Finding, HTTPResult

DEFAULT_PARAMS = [
    "id", "userId", "accountId", "orderId", "page", "limit", "offset", "q", "search", "sort",
    "redirect", "redirect_uri", "next", "callback", "returnUrl", "locale", "lang", "debug", "token", "client_id",
]


def mine_parameters(context, endpoints: list[dict], candidate_params: list[str] | None = None, max_params: int = 20) -> list[Finding]:
    http_client = context["http_client"]
    scope = context["scope"]
    storage = context["storage"]
    params = list(dict.fromkeys(candidate_params or DEFAULT_PARAMS))[:max_params]
    findings: list[Finding] = []
    for endpoint in endpoints:
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        if method != "GET" or not scope.should_request("GET", url)[0]:
            continue
        baseline = http_client.safe_request("GET", url)
        for param in params:
            marker = f"raven-param-{uuid4().hex[:8]}"
            test_url = add_param(url, param, marker)
            result = http_client.safe_request("GET", test_url)
            signal = parameter_signal(baseline, result, marker)
            storage.append_jsonl("param_miner.jsonl", {"url": test_url, "param": param, "signal": signal, "status_code": result.status_code})
            if signal["interesting"]:
                findings.append(
                    Finding(
                        title="Hidden parameter signal",
                        severity="low",
                        endpoint=url,
                        description="Un parametre ajoute modifie la reponse ou reflete un marqueur safe.",
                        proof=f"param={param}, signal={signal}",
                        curl_command=result.curl_command,
                        score=4,
                        category="param",
                        confidence="medium",
                        reason="parameter changed response/reflection/error behavior",
                        evidence=str(signal),
                        next_step="Verifier manuellement le role du parametre sans brute force.",
                        tags=["param-miner", param],
                    )
                )
    storage.save_findings(findings)
    return findings


def add_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[name] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def parameter_signal(baseline: HTTPResult, result: HTTPResult, marker: str) -> dict:
    reflected = marker in (result.body_text or result.body_preview or "")
    status_changed = baseline.status_code != result.status_code
    size_delta = abs(baseline.size - result.size)
    hash_changed = baseline.body_hash != result.body_hash
    verbose_error = any(token in (result.body_text or result.body_preview or "").lower() for token in ("exception", "traceback", "stack trace", "typeerror"))
    return {
        "interesting": reflected or status_changed or verbose_error or (hash_changed and size_delta > 80),
        "reflected": reflected,
        "status_changed": status_changed,
        "size_delta": size_delta,
        "hash_changed": hash_changed,
        "verbose_error": verbose_error,
    }
