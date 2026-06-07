"""Conservative OAuth redirect parameter detector."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.models import Finding

PARAMETERS = {"redirect_uri", "redirect_url", "callback", "returnUrl", "return_url", "next", "continue", "url"}


def run_oauth(context) -> list[Finding]:
    target = context["target"]
    parsed = urlparse(target)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    candidates = PARAMETERS.intersection(params)
    findings: list[Finding] = []
    for param in candidates:
        modified = params.copy()
        modified[param] = "https://example.org"
        test_url = urlunparse(parsed._replace(query=urlencode(modified)))
        if not context["scope"].is_allowed_url(test_url):
            continue
        try:
            result = context["http_client"].get(test_url)
        except Exception:
            continue
        if result.redirect_url and "example.org" in result.redirect_url:
            findings.append(
                Finding(
                    title="Redirection externe potentiellement acceptee",
                    severity="medium",
                    endpoint=target,
                    description="Un parametre de redirection semble accepter une URL externe de test.",
                    proof=f"{param} -> {result.redirect_url}",
                    curl_command=result.curl_command,
                    score=4,
                    tags=["oauth", "redirect"],
                )
            )
    context["storage"].write_json("oauth_results.json", [finding.to_dict() for finding in findings])
    context["storage"].save_findings(findings)
    return findings
