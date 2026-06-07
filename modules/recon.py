"""Lightweight live host reconnaissance."""

from __future__ import annotations

from core.banner import print_finding, print_section
from core.models import Finding


def run_recon(context) -> list[Finding]:
    target = context["target"]
    storage = context["storage"]
    http_client = context["http_client"]
    result = http_client.get(target)
    if result.status_code == 0:
        storage.write_json("recon_results.json", [result.to_dict()])
        findings = [
            Finding(
                title="Erreur HTTP pendant le scan",
                severity="informational",
                endpoint=target,
                description="La requete n'a pas abouti. Si la cible est un lab/CTF avec certificat self-signed, relancer avec --insecure.",
                proof=result.body_preview or result.important_headers.get("error", "request error"),
                curl_command=result.curl_command,
                score=0,
                tags=["recon", "http-error"],
            )
        ]
        storage.save_findings(findings)
        return findings

    storage.append_line("urls.txt", result.url)
    if result.status_code < 500:
        storage.append_line("live_hosts.txt", result.url)
    storage.write_json("recon_results.json", [result.to_dict()])
    print_section("Recon result")
    print_finding(result.status_code, result.url, result.size, result.words, result.lines, 1 if result.status_code < 500 else 0, result.title)

    interesting = result.status_code in {200, 204, 301, 302, 307, 308, 401, 403}
    findings = [
        Finding(
            title=f"Host detecte ({result.status_code})",
            severity="informational",
            endpoint=result.url,
            description="La cible repond. Utilise crawl/js/api/fuzz/workflow pour une reconnaissance plus large.",
            proof=f"Status {result.status_code}, size {result.size}, words {result.words}, title {result.title or 'n/a'}",
            curl_command=result.curl_command,
            score=1 if interesting else 0,
            tags=["recon", "interesting-status" if interesting else "baseline"],
        )
    ]
    storage.save_findings(findings)
    return findings
