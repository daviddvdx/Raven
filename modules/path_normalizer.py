"""Safe path normalization comparison."""

from __future__ import annotations

from urllib.parse import quote

from core.models import Finding


def build_variants(base: str, path: str) -> list[str]:
    clean_base = base.rstrip("/")
    clean_path = "/" + path.lstrip("/")
    encoded_last = quote(clean_path.strip("/").split("/")[-1])
    return [
        f"{clean_base}{clean_path}",
        f"{clean_base}{clean_path.replace('/', '/./', 1)}",
        f"{clean_base}{clean_path.replace('/', '//', 1)}",
        f"{clean_base}/%2e{clean_path}",
        f"{clean_base}/%2e%2e{clean_path}",
        f"{clean_base}{clean_path}/",
        f"{clean_base}/{encoded_last}",
    ]


def run_normalize(context, base: str, path: str) -> list[Finding]:
    http_client = context["http_client"]
    storage = context["storage"]
    results = []
    for url in build_variants(base, path):
        if not context["scope"].is_allowed_url(url):
            continue
        try:
            results.append(http_client.get(url))
        except Exception:
            continue
    signatures = {(item.status_code, item.size, item.body_hash, item.redirect_url) for item in results}
    findings: list[Finding] = []
    if len(signatures) > 1:
        findings.append(
            Finding(
                title="Incoherence de normalisation de chemin",
                severity="informational",
                endpoint=f"{base.rstrip('/')}/{path.lstrip('/')}",
                description="Plusieurs variantes de chemin retournent des signatures differentes.",
                proof=f"{len(signatures)} signatures pour {len(results)} variantes",
                curl_command=results[0].curl_command if results else "",
                score=3,
                tags=["normalize"],
            )
        )
    storage.write_json("normalize_results.json", [item.to_dict() for item in results])
    storage.save_findings(findings)
    return findings
