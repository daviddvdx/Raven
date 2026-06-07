"""Lightweight live host reconnaissance."""

from __future__ import annotations

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
    findings: list[Finding] = []
    if result.status_code in {200, 204, 301, 302, 307, 308, 401, 403}:
        findings.append(
            Finding(
                title=f"Host vivant ({result.status_code})",
                severity="informational",
                endpoint=result.url,
                description="La cible repond et peut etre analysee plus finement.",
                proof=f"Status {result.status_code}, size {result.size}, title {result.title or 'n/a'}",
                curl_command=result.curl_command,
                score=1,
                tags=["recon"],
            )
        )
    storage.save_findings(findings)
    return findings
