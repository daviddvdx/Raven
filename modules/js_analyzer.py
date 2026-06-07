"""JavaScript endpoint and keyword analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup

from core.knowledge_loader import KnowledgeLoader
from core.models import Finding
from core.result import Endpoint
from core.scoring import score_exploitdb_match
from core.utils import mask_secret, resolve_url

ABSOLUTE_URL_RE = re.compile(r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PATH_RE = re.compile(r"(?P<quote>['\"])(/[a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%-]{2,})(?P=quote)")
FETCH_RE = re.compile(r"\bfetch\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
AXIOS_RE = re.compile(r"\baxios\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
XHR_RE = re.compile(r"\.open\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
WINDOW_URL_RE = re.compile(r"window\.[A-Z0-9_]*URL[A-Z0-9_]*\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
API_KEY_RE = re.compile(r"(?i)(api[_-]?key|token|secret|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]")
HISTORICAL_PATH_MARKERS = ("admin", "upload", "file", "download", "debug", "actuator", "openapi", "swagger", "graphql", "realms", "openid-connect")


def load_keywords() -> list[str]:
    path = Path("knowledge/js_keywords.txt")
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def collect_js_files(context, target: str) -> list[str]:
    scope = context["scope"]
    http_client = context["http_client"]
    if target.endswith(".js"):
        return [target]
    try:
        result = http_client.get(target)
        page = result.body_text or "" if "text/html" in (result.content_type or "") else ""
    except Exception:
        return []
    soup = BeautifulSoup(page, "html.parser")
    js_files: set[str] = set()
    for script in soup.find_all("script", src=True):
        js_url = resolve_url(target, script["src"])
        if scope.is_allowed_url(js_url):
            js_files.add(js_url)
    return sorted(js_files)


def analyze_javascript(context, js_files: list[str] | None = None) -> dict[str, list[str]]:
    storage = context["storage"]
    http_client = context["http_client"]
    scope = context["scope"]
    keywords = load_keywords()
    exploit_patterns = KnowledgeLoader().load_exploitdb_patterns()
    files = js_files or collect_js_files(context, context["target"])
    endpoints: set[str] = set()
    findings: list[Finding] = []
    keyword_hits: list[str] = []
    exploitdb_pattern_hits: list[dict] = []

    for js_url in files:
        if not scope.is_allowed_url(js_url):
            continue
        storage.append_line("js_files.txt", js_url)
        try:
            result = http_client.get(js_url)
            body = result.body_text or ""
        except Exception:
            continue
        for absolute in ABSOLUTE_URL_RE.findall(body):
            if scope.is_allowed_url(absolute):
                endpoints.add(absolute)
        candidate_paths = [match.group(2) for match in PATH_RE.finditer(body)]
        candidate_paths.extend(match.group(1) for regex in (FETCH_RE, AXIOS_RE, XHR_RE, WINDOW_URL_RE) for match in regex.finditer(body))
        for path in candidate_paths:
            if any(token in path for token in ("/api", "/v1/", "/v2/", "/admin", "/internal", "/private")):
                endpoints.add(resolve_url(js_url, path))
        for keyword in keywords:
            if keyword and keyword.lower() in body.lower():
                keyword_hits.append(f"{js_url}: {keyword}")
        hits = detect_exploitdb_js_patterns(js_url, body, exploit_patterns)
        exploitdb_pattern_hits.extend(hits)
        for hit in hits:
            if hit.get("score", {}).get("score", 0) >= 4:
                score = hit["score"]
                findings.append(
                    Finding(
                        title="Pattern historique Exploit-DB observe dans JavaScript",
                        severity="informational",
                        endpoint=js_url,
                        description="Le JavaScript contient un chemin, parametre ou alias technologie historiquement associe a des classes de vulnerabilites publiques.",
                        proof=f"class={hit.get('vulnerability_class')} patterns={hit.get('matched_patterns')}",
                        curl_command=result.curl_command,
                        score=score["score"],
                        category="exploit_pattern",
                        confidence=score["confidence"],
                        reason=score["reason"],
                        evidence=score["evidence"],
                        next_step=score["next_step"],
                        tags=["js", "exploitdb-pattern"],
                    )
                )
        risky_matches = JWT_RE.findall(body) + API_KEY_RE.findall(body)
        if risky_matches:
            previews = [mask_secret(match if isinstance(match, str) else str(match)) for match in risky_matches[:5]]
            findings.append(
                Finding(
                    title="Secret potentiel dans JavaScript public",
                    severity="medium",
                    endpoint=js_url,
                    description="Un motif sensible potentiel a ete detecte dans un fichier JavaScript public. Ne pas l'utiliser, valider manuellement.",
                    proof=f"{len(risky_matches)} motif(s) potentiel(s), previews={previews}, hash {result.body_hash}",
                    curl_command=result.curl_command,
                    score=5,
                    tags=["js", "secret-potential"],
                )
            )
        if any(marker in body.lower() for marker in ("swagger", "openapi", "api-docs", "graphql", "oauth", "oidc")):
            findings.append(
                Finding(
                    title="Surface API referencee dans JavaScript",
                    severity="informational",
                    endpoint=js_url,
                    description="Le JavaScript mentionne Swagger, OpenAPI, GraphQL, OAuth ou OIDC.",
                    proof="Mots-cles API detectes dans le fichier.",
                    curl_command=result.curl_command,
                    score=3,
                    tags=["js", "api"],
                )
            )

    for endpoint in sorted(endpoints):
        storage.append_line("js_endpoints.txt", endpoint)
        storage.append_jsonl("js_endpoints.jsonl", {"url": endpoint, "source": "js", "type": classify_js_endpoint(endpoint)})
        storage.save_endpoint(Endpoint(endpoint, classify_js_endpoint(endpoint), "js").to_dict())
    storage.write_json("js_exploitdb_patterns.json", exploitdb_pattern_hits)
    storage.write_text("js_findings.md", render_js_markdown(files, endpoints, keyword_hits, findings))
    storage.save_findings(findings)
    return {"js_files": sorted(files), "endpoints": sorted(endpoints), "keyword_hits": keyword_hits}


def classify_js_endpoint(url: str) -> str:
    lower = url.lower()
    if any(token in lower for token in ("/api", "/graphql", "/v1/", "/v2/")):
        return "api"
    if any(token in lower for token in ("/oauth", "/openid", "redirect_uri", "/login")):
        return "auth"
    if any(lower.endswith(ext) for ext in (".js", ".map", ".css", ".png", ".svg")):
        return "static"
    return "web"


def detect_exploitdb_js_patterns(js_url: str, body: str, patterns: dict) -> list[dict]:
    lower = body.lower()
    hits: list[dict] = []
    tech_aliases = patterns.get("technology_aliases", {})
    classes = patterns.get("vulnerability_classes", {})
    risk_modifiers = patterns.get("risk_modifiers", {})
    detected_tech = [tech for tech, aliases in tech_aliases.items() if any(alias.lower() in lower for alias in aliases)]
    historical_paths = [marker for marker in HISTORICAL_PATH_MARKERS if marker in lower]
    high_value_paths = [path for path in risk_modifiers.get("high_value_paths", []) if path.lower() in lower]
    for vuln_class, data in classes.items():
        matched_patterns: list[str] = []
        for param in data.get("interesting_params", []):
            if re.search(rf"[\?&'\"]{re.escape(param)}(?:=|['\"])", body, re.IGNORECASE) or param.lower() in lower:
                matched_patterns.append(f"param:{param}")
        for path in data.get("interesting_paths", []) + data.get("interesting_files", []):
            if path.lower() in lower:
                matched_patterns.append(f"path:{path}")
        if vuln_class == "auth_bypass" and any(token in lower for token in ("/admin", "/login", "/account")):
            matched_patterns.append("auth-path")
        if vuln_class == "open_redirect" and any(token in lower for token in ("redirect_uri", "next", "callback")):
            matched_patterns.append("redirect-param")
        if vuln_class == "lfi" and any(token in lower for token in ("file=", "path=", "template=", "lang=")):
            matched_patterns.append("file-param")
        if vuln_class == "xss" and any(token in lower for token in ("search", "comment", "message", "query")):
            matched_patterns.append("xss-param")
        if not matched_patterns and not high_value_paths and not historical_paths:
            continue
        score = score_exploitdb_match(
            {"technology": ",".join(detected_tech), "vulnerability_class": vuln_class},
            {
                "technology": ",".join(detected_tech),
                "vulnerability_class": vuln_class,
                "exploitdb_matches": len(detected_tech),
                "endpoint_compatible": bool(matched_patterns or high_value_paths),
                "param_match": any(item.startswith("param:") for item in matched_patterns),
                "sensitive_pattern": bool(high_value_paths or historical_paths),
                "matched_patterns": matched_patterns + historical_paths + high_value_paths,
                "nominal_only": not matched_patterns and bool(detected_tech),
            },
        )
        hits.append(
            {
                "source": js_url,
                "technologies": detected_tech,
                "vulnerability_class": vuln_class,
                "matched_patterns": matched_patterns + historical_paths + high_value_paths,
                "score": score.to_dict(),
            }
        )
    return hits


def render_js_markdown(files: list[str], endpoints: set[str], keyword_hits: list[str], findings: list[Finding]) -> str:
    lines = ["# RAVEN JavaScript Findings", "", "## Files", ""]
    lines.extend(f"- {item}" for item in sorted(files))
    lines.extend(["", "## Endpoints", ""])
    lines.extend(f"- {item}" for item in sorted(endpoints))
    lines.extend(["", "## Keyword hits", ""])
    lines.extend(f"- {item}" for item in keyword_hits[:200])
    lines.extend(["", "## Potential findings", ""])
    lines.extend(f"- [{finding.severity}] {finding.title} - {finding.endpoint}" for finding in findings)
    return "\n".join(lines) + "\n"


def run_js(context) -> list[Finding]:
    data = analyze_javascript(context)
    findings = [
        Finding(
            title="Analyse JavaScript terminee",
            severity="informational",
            endpoint=context["target"],
            description="Les fichiers JavaScript visibles ont ete analyses.",
            proof=f"{len(data['js_files'])} fichier(s), {len(data['endpoints'])} endpoint(s)",
            score=1,
            tags=["js"],
        )
    ]
    context["storage"].save_findings(findings)
    return findings
