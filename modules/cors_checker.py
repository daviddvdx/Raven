"""CORS misconfiguration checks using safe origins only."""

from __future__ import annotations

from core.models import Finding

TEST_ORIGINS = ["https://evil.example", "null", "https://attacker.com"]


def run_cors(context) -> list[Finding]:
    http_client = context["http_client"]
    storage = context["storage"]
    target = context["target"]
    findings: list[Finding] = []
    for origin in TEST_ORIGINS:
        try:
            result = http_client.get(target, headers={"Origin": origin})
        except Exception:
            continue
        headers = {k.lower(): v for k, v in result.important_headers.items()}
        acao = headers.get("access-control-allow-origin")
        creds = headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao == origin or acao == "*":
            severity = "high" if creds and acao == origin else "medium" if creds else "low"
            findings.append(
                Finding(
                    title="Configuration CORS permissive potentielle",
                    severity=severity,
                    endpoint=target,
                    description="La reponse CORS accepte ou reflete une origine de test.",
                    proof=f"Origin={origin}, ACAO={acao}, credentials={creds}",
                    curl_command=result.curl_command,
                    score=4 if severity in {"medium", "high"} else 2,
                    tags=["cors"],
                )
            )
    storage.write_json("cors_results.json", [finding.to_dict() for finding in findings])
    storage.save_findings(findings)
    return findings
