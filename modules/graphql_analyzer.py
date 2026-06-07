"""Controlled GraphQL checks."""

from __future__ import annotations

from core.models import Finding


def run_graphql(context) -> list[Finding]:
    http_client = context["http_client"]
    storage = context["storage"]
    target = context["target"]
    findings: list[Finding] = []
    try:
        typename = http_client.post(target, json={"query": "{__typename}"})
        if typename.status_code == 200 and "__typename" in (typename.body_preview or ""):
            findings.append(
                Finding(
                    title="Endpoint GraphQL accessible",
                    severity="informational",
                    endpoint=target,
                    description="La requete GraphQL minimale {__typename} obtient une reponse.",
                    proof=f"status={typename.status_code} size={typename.size}",
                    curl_command=typename.curl_command,
                    score=3,
                    tags=["graphql"],
                )
            )
    except Exception:
        pass
    try:
        introspection = http_client.post(target, json={"query": "query { __schema { queryType { name } } }"})
        if introspection.status_code == 200 and "__schema" in (introspection.body_preview or ""):
            findings.append(
                Finding(
                    title="Introspection GraphQL potentiellement ouverte",
                    severity="medium",
                    endpoint=target,
                    description="Une requete d'introspection controlee semble retourner un schema.",
                    proof=f"status={introspection.status_code} size={introspection.size}",
                    curl_command=introspection.curl_command,
                    score=5,
                    tags=["graphql", "introspection"],
                )
            )
    except Exception:
        pass
    storage.write_json("graphql_results.json", [finding.to_dict() for finding in findings])
    storage.save_findings(findings)
    return findings
