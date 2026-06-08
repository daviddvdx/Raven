"""Markdown/JSON/CSV report generation."""

from __future__ import annotations

import csv
import json
from io import StringIO
from urllib.parse import urlparse


def load_json(path):
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def load_lines(path):
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def load_jsonl(path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def generate_report(context, output_format: str = "markdown") -> str:
    storage = context["storage"]
    findings = load_json(storage.path("findings.json"))
    findings.sort(key=lambda item: item.get("score", 0), reverse=True)
    if output_format == "json":
        path = storage.write_json("reports/report.json", findings)
        return str(path)
    if output_format == "csv":
        buffer = StringIO()
        fieldnames = ["title", "severity", "endpoint", "score", "status", "description", "proof", "curl_command"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow({key: finding.get(key, "") for key in fieldnames})
        path = storage.write_text("reports/report.csv", buffer.getvalue())
        return str(path)
    markdown = render_markdown(context, findings)
    path = storage.write_text("findings.md", markdown)
    storage.write_text("reports/report.md", markdown)
    storage.write_json("reports/report.json", {"findings": findings, "summary": {"findings_count": len(findings)}})
    storage.write_text("reports/findings.csv", render_findings_csv(findings))
    return str(path)


def render_findings_csv(findings: list[dict]) -> str:
    buffer = StringIO()
    fieldnames = ["title", "severity", "confidence", "endpoint", "category", "score", "reason", "evidence", "recommendation"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in findings:
        writer.writerow({key: finding.get(key, "") for key in fieldnames})
    return buffer.getvalue()


def render_markdown(context, findings: list[dict]) -> str:
    storage = context["storage"]
    scope = context.get("scope")
    urls = load_lines(storage.path("urls.txt"))
    live_hosts = load_lines(storage.path("live_hosts.txt"))
    js_files = load_lines(storage.path("js_files.txt"))
    js_endpoints = load_lines(storage.path("js_endpoints.txt"))
    api_endpoints = load_lines(storage.path("api_endpoints.txt"))
    filtered_noise = load_json(storage.path("filtered_noise.json"))
    baselines = load_json(storage.path("baselines/fuzz_baseline.json"))
    wordlists_used = load_json(storage.path("wordlists_used.json"))
    run_config = load_json(storage.path("run_config.json"))
    run_config = run_config if isinstance(run_config, dict) else {}
    workflow_plan = load_json(storage.path("workflow_plan.json"))
    workflow_plan = workflow_plan if isinstance(workflow_plan, dict) else {}
    idor_matrix = load_json(storage.path("idor_matrix.json"))
    xss_reflections = load_json(storage.path("xss_reflections.json"))
    js_exploitdb_patterns = load_json(storage.path("js_exploitdb_patterns.json"))
    api_exploitdb_patterns = load_json(storage.path("api_exploitdb_patterns.json"))
    raw_results = load_jsonl(storage.path("raw/http_results.jsonl"))
    waf_observed = sorted({tech for row in raw_results for tech in row.get("technologies", []) if tech in {"Cloudflare", "Akamai", "Fastly", "CloudFront"}})
    api_grouped = group_api_endpoints([*api_endpoints, *js_endpoints])
    top_findings = findings[:10]
    lines = [
        "# RAVEN Report",
        "",
        "## 1. Resume executif",
        "",
        f"Projet: {storage.project}",
        f"Findings potentiels: {len(findings)}",
        "",
        "## Top findings a verifier",
        "",
    ]
    for finding in top_findings:
        lines.extend(
            [
                f"- [{finding.get('score', 0)}][{finding.get('confidence', 'low')}] {finding.get('title', 'Finding')} - {finding.get('endpoint', '')}",
                f"  Reason: {finding.get('reason', finding.get('description', ''))}",
                f"  Next: {finding.get('next_step', 'Verifier manuellement.')}",
            ]
        )
    lines.extend(
        [
            "",
            "## 2. Scope utilise",
            "",
            f"Programme: {scope.program if scope else 'n/a'}",
            f"Domaines autorises: {', '.join(scope.allowed_domains) if scope else 'n/a'}",
            "",
            "## 3. Methodologie",
            "",
            "Reconnaissance douce, validation stricte du scope, collecte d'URLs, analyse JavaScript, fuzzing controle et tri par score.",
            "",
            "## Profil de bruit utilise",
            "",
        f"Profil: {context.get('profile') or run_config.get('Profile', 'non enregistre')}",
            f"Niveau de bruit workflow: {workflow_plan.get('noise_level', 'n/a')}",
            "",
            "## Workflow Decisions",
            "",
        ]
    )
    if workflow_plan:
        lines.extend(
            [
                f"- Dry-run: {workflow_plan.get('dry_run', False)}",
                f"- Profil: {workflow_plan.get('profile', 'n/a')}",
                f"- Noise: {workflow_plan.get('noise_level', 'n/a')}",
                f"- Filtres: {workflow_plan.get('filters', {})}",
                f"- Rate limit: {workflow_plan.get('rate_limit', {})}",
                f"- Confirmations fortes: {workflow_plan.get('strong_confirmations', {})}",
            ]
        )
        for step, enabled in workflow_plan.get("steps", {}).items():
            reason = workflow_plan.get("skipped_reasons", {}).get(step, "")
            lines.append(f"- {step}: {'launched' if enabled else 'skipped'} {reason}")
    else:
        lines.append("- No workflow plan recorded.")
    lines.extend(
        [
            "",
            "## Wordlists utilisees",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in wordlists_used)
    lines.extend(
        [
            "",
            "## Baselines utilisees",
            "",
        ]
    )
    lines.extend(f"- status={item.get('status_code')} size={item.get('size')} words={item.get('words')} hash={str(item.get('body_hash', ''))[:12]}" for item in baselines)
    lines.extend(
        [
            "",
            "## Resultats filtres comme bruit",
            "",
        ]
    )
    lines.extend(f"- {item.get('url')} - {item.get('reason')}" for item in filtered_noise[:200])
    lines.extend(
        [
            "",
            "## WAF/CDN observe",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in waf_observed)
    lines.extend(
        [
            "",
            "## Exploit-DB Intelligence Summary",
            "",
            "RAVEN utilise uniquement les metadonnees locales Exploit-DB/SearchSploit pour prioriser les validations manuelles. Aucun PoC n'est execute ou inclus.",
            "",
            "## Technologies with public exploit references",
            "",
        ]
    )
    exploit_findings = [finding for finding in findings if finding.get("category") in {"exploitdb_match", "cve_match", "known_vulnerable_technology", "exploit_pattern"} or "exploitdb" in finding.get("tags", [])]
    for finding in exploit_findings[:50]:
        lines.append(f"- score={finding.get('score', 0)} {finding.get('endpoint', '')} - {finding.get('reason', '')}")
    lines.extend(["", "## CVE/EDB correlations", ""])
    for finding in exploit_findings[:50]:
        evidence = finding.get("evidence", "")
        if "CVE-" in evidence or "cves" in evidence:
            lines.append(f"- {finding.get('endpoint', '')}: {evidence}")
    lines.extend(["", "## Historical vulnerability classes observed", ""])
    observed_classes = sorted({item.get("vulnerability_class", "") for item in [*js_exploitdb_patterns, *api_exploitdb_patterns] if item.get("vulnerability_class")})
    lines.extend(f"- {item}" for item in observed_classes)
    lines.extend(["", "## Exploit-pattern-based candidates", ""])
    for item in js_exploitdb_patterns[:50]:
        lines.append(f"- JS {item.get('source')} class={item.get('vulnerability_class')} score={item.get('score', {}).get('score', 0)}")
    for item in api_exploitdb_patterns[:50]:
        lines.append(f"- API {item.get('endpoint')} tags={', '.join(item.get('endpoint_risk_tags', []))} score={item.get('score', {}).get('score', 0)}")
    lines.extend(
        [
            "",
            "## Exploit-DB Manual verification checklist",
            "",
            "- Confirmer la technologie et sa version exacte.",
            "- Lire manuellement le PoC local si le programme l'autorise, sans l'executer.",
            "- Verifier que l'endpoint est dans le scope et que le test est autorise.",
            "- Reproduire uniquement des checks non destructifs par defaut.",
            "",
            "## Exploit-DB Safety notes",
            "",
            "- Aucun exploit n'est execute automatiquement.",
            "- Aucun payload agressif n'est genere par defaut.",
            "- Le rapport ne contient que titre, classe, score, CVE/EDB et resume sûr.",
            "",
        "## 4. Hosts testes",
        "",
        ]
    )
    lines.extend(f"- {item}" for item in live_hosts[:200])
    lines.extend(["", "## 5. Endpoints decouverts", ""])
    lines.extend(f"- {item}" for item in urls[:500])
    lines.extend(["", "## 6. Fichiers JS analyses", ""])
    lines.extend(f"- {item}" for item in js_files[:300])
    lines.extend(["", "## 7. APIs detectees", ""])
    lines.extend(f"- {item}" for item in js_endpoints[:300])
    lines.extend(["", "## API endpoints regroupes par ressource", ""])
    for resource, endpoints in api_grouped.items():
        lines.append(f"### {resource}")
        lines.extend(f"- {item}" for item in endpoints[:50])
    lines.extend(["", "## Endpoints IDOR candidates", ""])
    for row in idor_matrix[:100]:
        lines.append(f"- {row.get('endpoint')} score={row.get('score', {}).get('score', 0)} similarity={row.get('similarity', '-')}")
    lines.extend(["", "## Reflections XSS candidates", ""])
    for row in xss_reflections[:100]:
        if row.get("context", {}).get("reflected"):
            lines.append(f"- {row.get('url')} param={row.get('param')} score={row.get('score', {}).get('score', 0)}")
    lines.extend(["", "## 8. Findings potentiels", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('title', 'Finding')}",
                "",
                f"- Severite estimee: {finding.get('severity', 'informational')}",
                f"- Score: {finding.get('score', 0)}",
                f"- Categorie: {finding.get('category', 'endpoint')}",
                f"- Confiance: {finding.get('confidence', 'low')}",
                f"- Endpoint: {finding.get('endpoint', '')}",
                f"- Statut: {finding.get('status', 'a verifier')}",
                f"- Description: {finding.get('description', '')}",
                f"- Preuve: {finding.get('proof', '')}",
                f"- Raison: {finding.get('reason', '')}",
                f"- Prochaine action: {finding.get('next_step', 'Verifier manuellement.')}",
                "",
            ]
        )
    lines.extend(["## 9. Preuves techniques", ""])
    lines.extend(f"- {finding.get('proof', '')}" for finding in findings[:100])
    lines.extend(["", "## 10. Commandes curl reproductibles", ""])
    lines.extend(f"```bash\n{finding.get('curl_command', '')}\n```" for finding in findings if finding.get("curl_command"))
    lines.extend(["", "## 11. Impact potentiel", "", "Les impacts doivent etre confirmes manuellement dans le cadre autorise."])
    lines.extend(["", "## 12. Recommandations", "", "Verifier les ressources exposees, confirmer les faux positifs et documenter les preuves reproductibles."])
    lines.extend(
        [
            "",
            "## 13. Points a verifier manuellement",
            "",
            "- Authentification attendue",
            "- Exposition involontaire",
            "- Difference entre environnements",
            "",
            "## Prochaines actions manuelles",
            "",
            "- Rejouer les commandes curl prioritaires dans Burp Suite.",
            "- Confirmer les candidats IDOR/BOLA avec des comptes explicitement autorises.",
            "- Valider les reflections XSS sans execution navigateur automatique.",
            "- Conserver les limites du programme Bug Bounty comme source de verite.",
            "",
        ]
    )
    return "\n".join(lines)


def group_api_endpoints(endpoints: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for endpoint in sorted(set(endpoints)):
        parsed = urlparse(endpoint)
        parts = [part for part in parsed.path.split("/") if part]
        resource = parts[0] if parts else "root"
        if resource in {"api", "v1", "v2"} and len(parts) > 1:
            resource = f"{resource}/{parts[1]}"
        grouped.setdefault(resource, []).append(endpoint)
    return grouped
