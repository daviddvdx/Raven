"""Safe API surface checks."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from core.knowledge_loader import KnowledgeLoader
from core.models import Finding
from core.scoring import score_exploitdb_match
from core.utils import resolve_url


COMMON_API_DOCS = ["swagger.json", "openapi.json", "api-docs", "swagger-ui.html", "robots.txt", ".well-known/security.txt", "sitemap.xml"]


def run_api(context) -> list[Finding]:
    storage = context["storage"]
    http_client = context["http_client"]
    target = context["target"].rstrip("/")
    exploit_patterns = KnowledgeLoader().load_exploitdb_patterns()
    endpoint_enrichment: list[dict] = []
    findings: list[Finding] = []
    try:
        options = http_client.options(target)
        allow = options.important_headers.get("allow") or options.important_headers.get("Allow")
        if allow:
            findings.append(
                Finding(
                    title="Methodes HTTP annoncees",
                    severity="informational",
                    endpoint=target,
                    description="La reponse OPTIONS expose les methodes autorisees.",
                    proof=f"Allow: {allow}",
                    curl_command=options.curl_command,
                    score=2,
                    tags=["api"],
                )
            )
    except Exception:
        pass
    for item in COMMON_API_DOCS:
        url = resolve_url(f"{target}/", item)
        if not context["scope"].is_allowed_url(url):
            continue
        try:
            result = http_client.get(url)
        except Exception:
            continue
        if result.status_code == 200:
            score = 5 if item in {"swagger.json", "openapi.json", "api-docs", "swagger-ui.html"} else 2
            enrichment = classify_api_endpoint(url, exploit_patterns)
            endpoint_enrichment.append(enrichment)
            score_data = enrichment.get("score", {})
            score = max(score, int(score_data.get("score", 0)))
            findings.append(
                Finding(
                    title=f"Ressource API exposee: {item}",
                    severity="low" if score >= 5 else "informational",
                    endpoint=url,
                    description="Une ressource de documentation ou de decouverte API est accessible.",
                    proof=f"status={result.status_code} size={result.size}",
                    curl_command=result.curl_command,
                    score=score,
                    category=score_data.get("category", "api"),
                    confidence=score_data.get("confidence", "low"),
                    reason=score_data.get("reason", "API documentation/resource exposed"),
                    evidence=score_data.get("evidence", f"status={result.status_code}"),
                    next_step=score_data.get("next_step", "Verify intended exposure manually."),
                    tags=["api", "docs", *enrichment.get("endpoint_risk_tags", [])],
                )
            )
            storage.append_line("api_endpoints.txt", url)
    storage.write_json("api_exploitdb_patterns.json", endpoint_enrichment)
    storage.write_json("api_results.json", [finding.to_dict() for finding in findings])
    storage.save_findings(findings)
    return findings


def classify_api_endpoint(endpoint: str, patterns: dict) -> dict:
    lower = endpoint.lower()
    parsed = urlparse(endpoint)
    params = {key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)}
    tags: list[str] = []
    matched_patterns: list[str] = []
    classes = patterns.get("vulnerability_classes", {})
    risk_modifiers = patterns.get("risk_modifiers", {})
    if any(token in lower for token in ("id=", "/users/", "/accounts/", "organization", "tenant")):
        tags.append("idor_candidate")
    if params.intersection(classes.get("xss", {}).get("interesting_params", [])):
        tags.append("xss_reflection_candidate")
    if params.intersection(classes.get("open_redirect", {}).get("interesting_params", [])):
        tags.append("open_redirect_candidate")
    if params.intersection(classes.get("lfi", {}).get("interesting_params", [])) or any(token in lower for token in ("download", "file", "export")):
        tags.append("file_access_candidate")
    if any(path in lower for path in classes.get("file_upload", {}).get("interesting_paths", [])):
        tags.append("upload_candidate")
    if any(path in lower for path in classes.get("auth_bypass", {}).get("interesting_paths", [])):
        tags.append("auth_bypass_candidate")
    for path in risk_modifiers.get("high_value_paths", []):
        if path.lower() in lower:
            tags.append("known_exploit_pattern")
            matched_patterns.append(path)
    for action in risk_modifiers.get("sensitive_actions", []):
        if action.lower() in lower:
            matched_patterns.append(action)
    score = score_exploitdb_match(
        {"vulnerability_class": ",".join(tags)},
        {
            "vulnerability_class": ",".join(tags),
            "exploitdb_matches": 0,
            "endpoint_compatible": bool(tags),
            "param_match": bool(params),
            "sensitive_pattern": bool(matched_patterns),
            "matched_patterns": matched_patterns + tags,
            "active_validation_not_allowed": False,
        },
    )
    return {"endpoint": endpoint, "endpoint_risk_tags": sorted(set(tags)), "matched_patterns": matched_patterns, "score": score.to_dict()}
