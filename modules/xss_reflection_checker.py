"""Safe XSS reflection checker without browser execution."""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.exploitdb_manager import ExploitDBManager
from core.knowledge_loader import KnowledgeLoader
from core.models import Finding
from core.scoring import score_xss


def build_probe_urls(target: str, probes: list[str], interesting_params: set[str], max_payloads: int = 5) -> list[tuple[str, str, str]]:
    parsed = urlparse(target)
    output: list[tuple[str, str, str]] = []
    selected = probes[: max(1, max_payloads)]
    if "FUZZ" in target:
        for probe in selected:
            output.append((target.replace("FUZZ", probe), "FUZZ", probe))
        return output
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    target_params = [name for name in params if name in interesting_params] or list(params)
    for name in target_params:
        for probe in selected:
            modified = params.copy()
            modified[name] = probe
            output.append((urlunparse(parsed._replace(query=urlencode(modified))), name, probe))
    return output


def detect_reflection_context(body: str, probe: str, content_type: str | None) -> dict:
    encoded = html.escape(probe)
    reflected = probe in body or encoded in body
    script_context = bool(re.search(r"<script[^>]*>.*?" + re.escape(probe) + r".*?</script>", body, re.IGNORECASE | re.DOTALL))
    html_attribute = bool(re.search(r"<[^>]+\s+[a-zA-Z:-]+=[\"'][^\"']*" + re.escape(probe) + r"[^\"']*[\"']", body))
    json_response = "json" in (content_type or "").lower()
    url_context = "%" in body and probe.replace("<", "%3C").lower() in body.lower()
    return {
        "reflected": reflected,
        "html_body": reflected and not script_context and not html_attribute and not json_response,
        "html_attribute": html_attribute,
        "script_context": script_context,
        "json_response": json_response,
        "url_context": url_context,
        "unencoded": probe in body,
        "encoded": encoded in body and encoded != probe,
        "safe_json": json_response and encoded not in body and "<" not in body,
    }


def load_payloads(payload_file: str | None, max_payloads: int, safe_only: bool) -> list[str]:
    loader = KnowledgeLoader()
    report_patterns = loader.load_report_patterns()
    exploit_patterns = loader.load_exploitdb_patterns()
    safe_probe = exploit_patterns.get("vulnerability_classes", {}).get("xss", {}).get("safe_probe")
    safe_probes = report_patterns.get("xss", {}).get("safe_probes", ["ravenxss", "raven-xss-test", "<ravenxss>"])
    if safe_probe:
        safe_probes = list(dict.fromkeys([safe_probe, *safe_probes]))
    if safe_only or not payload_file:
        return safe_probes[:max_payloads]
    custom = loader.load_payload_file(payload_file, max_payloads=max_payloads)
    return custom or safe_probes[:max_payloads]


def run_xss_reflection(
    context,
    payload_file: str | None = None,
    max_payloads: int = 5,
    safe_only: bool = True,
    no_browser_execution: bool = True,
) -> list[Finding]:
    storage = context["storage"]
    scope = context["scope"]
    target = context["target"]
    http_client = context["http_client"]
    loader = KnowledgeLoader()
    patterns = loader.load_report_patterns()
    exploit_patterns = loader.load_exploitdb_patterns()
    interesting_params = set(patterns.get("xss", {}).get("interesting_params", []))
    interesting_params.update(exploit_patterns.get("vulnerability_classes", {}).get("xss", {}).get("interesting_params", []))
    exploitdb = ExploitDBManager(profile=context.get("profile", "quiet"), metadata_only=True)
    probes = load_payloads(payload_file, max_payloads=max_payloads, safe_only=safe_only)
    candidates = build_probe_urls(target, probes, interesting_params, max_payloads=max_payloads)
    results: list[dict] = []
    findings: list[Finding] = []

    for url, param, probe in candidates:
        if not scope.is_allowed_url(url):
            results.append({"url": url, "param": param, "skipped": "out_of_scope"})
            continue
        try:
            result = http_client.get(url)
        except Exception as exc:
            results.append({"url": url, "param": param, "error": str(exc)})
            continue
        context_data = detect_reflection_context(result.body_text or "", probe, result.content_type)
        signals = {
            **context_data,
            "interesting_param": param in interesting_params or param == "FUZZ",
            "public_endpoint": result.status_code == 200,
            "no_browser_execution": no_browser_execution,
        }
        score_data = score_xss(signals)
        tech_xss_matches = []
        for tech in result.technologies:
            tech_xss_matches.extend(entry for entry in exploitdb.search_by_technology(tech) if entry.vulnerability_class == "xss")
        if tech_xss_matches and context_data["reflected"]:
            score_data.score = min(score_data.score + 2, 10)
            score_data.reason = f"{score_data.reason}, local Exploit-DB metadata has XSS references for detected technology"
            score_data.evidence = f"{score_data.evidence}; exploitdb_xss_matches={len(tech_xss_matches)}"
        row = {
            "url": result.url,
            "param": param,
            "probe": probe,
            "status_code": result.status_code,
            "size": result.size,
            "context": context_data,
            "score": score_data.to_dict(),
            "exploitdb_xss_matches": len(tech_xss_matches),
        }
        results.append(row)
        if context_data["reflected"] and score_data.score >= 4:
            findings.append(
                Finding(
                    title="Reflection XSS candidate",
                    severity="low" if score_data.score < 8 else "medium",
                    endpoint=result.url,
                    description="Un probe XSS non agressif est reflechi. Aucune execution navigateur n'a ete tentee.",
                    proof=f"param={param}, probe={probe}, context={context_data}",
                    curl_command=result.curl_command,
                    score=score_data.score,
                    category=score_data.category,
                    confidence=score_data.confidence,
                    reason=score_data.reason,
                    evidence=score_data.evidence,
                    next_step=score_data.next_step,
                    tags=["xss", "reflection"],
                )
            )

    storage.write_json("xss_reflections.json", results)
    storage.save_findings(findings)
    return findings
