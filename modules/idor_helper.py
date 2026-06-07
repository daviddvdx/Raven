"""Read-only IDOR/BOLA helper for authorized two-account comparisons."""

from __future__ import annotations

import base64
import json
import re
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from core.knowledge_loader import KnowledgeLoader
from core.models import Finding, HTTPResult
from core.scoring import score_idor

UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
NUMBER_RE = re.compile(r"(?<![a-zA-Z])\d{2,}(?![a-zA-Z])")


def requires_two_authorized_tokens(token_user_a: str | None, token_user_b: str | None) -> None:
    if not token_user_a or not token_user_b:
        raise ValueError("Le module IDOR exige deux tokens explicitement autorises: token_user_a et token_user_b.")


def load_endpoints(path: str | Path, max_endpoints: int = 200) -> list[str]:
    endpoint_path = Path(path)
    if not endpoint_path.exists():
        return []
    endpoints = [line.strip() for line in endpoint_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    return endpoints[:max(1, max_endpoints)]


def auth_headers(token: str) -> dict[str, str]:
    value = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    return {"Authorization": value}


def detect_graphql_global_id(value: str) -> bool:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return False
    return ":" in decoded and len(decoded) < 200


def endpoint_signals(endpoint: str, patterns: dict) -> dict:
    parsed = urlparse(endpoint)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    lower = endpoint.lower()
    idor_patterns = patterns.get("idor_bola", {})
    interesting_params = set(idor_patterns.get("interesting_params", []))
    risky_actions = set(idor_patterns.get("risky_actions", []))
    query_keys = set(query)
    query_values = set(query.values())
    has_uuid = bool(UUID_RE.search(endpoint))
    has_number = bool(NUMBER_RE.search(parsed.path))
    has_global_id = any(detect_graphql_global_id(value) for value in query_values)
    return {
        "interesting_param": bool(query_keys.intersection(interesting_params)),
        "path_identifier": has_uuid or has_number or has_global_id,
        "low_privilege_admin_200": any(token in lower for token in ("/admin", "/internal", "/private")),
        "sensitive_object_action": any(token in lower for token in ("download", "export", "invoice", "document", "file")),
        "state_changing": any(action in lower for action in risky_actions),
        "query_keys": sorted(query_keys),
    }


def exploitdb_idor_patterns(endpoint: str, exploit_patterns: dict) -> dict:
    lower = endpoint.lower()
    risk = exploit_patterns.get("risk_modifiers", {})
    historical = ["download", "export", "invoice", "document", "account", "organization", "tenant"]
    matched = [item for item in historical if item in lower]
    matched.extend(item for item in risk.get("sensitive_actions", []) if item.lower() in lower)
    return {"exploit_pattern": bool(matched), "exploitdb_matched_patterns": sorted(set(matched))}


def compare_json_fields(a_text: str | None, b_text: str | None) -> dict:
    try:
        a_json = json.loads(a_text or "{}")
        b_json = json.loads(b_text or "{}")
    except json.JSONDecodeError:
        return {"json": False, "shared_keys": [], "different_keys": []}
    if not isinstance(a_json, dict) or not isinstance(b_json, dict):
        return {"json": True, "shared_keys": [], "different_keys": []}
    shared = sorted(set(a_json).intersection(b_json))
    different = sorted(key for key in shared if a_json.get(key) != b_json.get(key))
    return {"json": True, "shared_keys": shared[:50], "different_keys": different[:50]}


def body_similarity(a: HTTPResult, b: HTTPResult) -> float:
    return SequenceMatcher(None, a.body_text or "", b.body_text or "").ratio()


def run_idor(
    context,
    endpoints_file: str,
    token_user_a: str,
    token_user_b: str,
    token_admin: str | None = None,
    allow_state_changing: bool = False,
    max_endpoints: int = 200,
) -> list[Finding]:
    requires_two_authorized_tokens(token_user_a, token_user_b)
    storage = context["storage"]
    scope = context["scope"]
    http_client = context["http_client"]
    loader = KnowledgeLoader()
    patterns = loader.load_report_patterns()
    exploit_patterns = loader.load_exploitdb_patterns()
    endpoints = load_endpoints(endpoints_file, max_endpoints=max_endpoints)
    matrix: list[dict] = []
    findings: list[Finding] = []

    for endpoint in endpoints:
        signals = endpoint_signals(endpoint, patterns)
        signals.update(exploitdb_idor_patterns(endpoint, exploit_patterns))
        signals["out_of_scope"] = not scope.is_allowed_url(endpoint)
        if signals["out_of_scope"]:
            matrix.append({"endpoint": endpoint, "skipped": "out_of_scope"})
            continue
        if signals["state_changing"] and not allow_state_changing:
            matrix.append({"endpoint": endpoint, "note": "state-changing action marker observed; GET-only comparison kept conservative"})
        try:
            result_a = http_client.get(endpoint, headers=auth_headers(token_user_a))
            result_b = http_client.get(endpoint, headers=auth_headers(token_user_b))
        except Exception as exc:
            matrix.append({"endpoint": endpoint, "error": str(exc)})
            continue
        similarity = body_similarity(result_a, result_b)
        json_diff = compare_json_fields(result_a.body_text, result_b.body_text)
        signals["both_200_same_object"] = result_a.status_code == 200 and result_b.status_code == 200 and similarity > 0.90
        signals["expected_forbidden_but_200"] = result_b.status_code == 200 and (signals["low_privilege_admin_200"] or signals["interesting_param"])
        signals["generic_error"] = result_a.status_code in {403, 404} and result_b.status_code in {403, 404} and result_a.body_hash == result_b.body_hash
        score_data = score_idor(signals)
        if signals.get("exploit_pattern"):
            score_data.score = min(score_data.score + 2, 10)
            score_data.reason = f"{score_data.reason}, historical Exploit-DB-style object/action pattern"
        row = {
            "endpoint": endpoint,
            "user_a_status": result_a.status_code,
            "user_b_status": result_b.status_code,
            "user_a_size": result_a.size,
            "user_b_size": result_b.size,
            "user_a_hash": result_a.body_hash,
            "user_b_hash": result_b.body_hash,
            "similarity": round(similarity, 3),
            "json_diff": json_diff,
            "signals": signals,
            "score": score_data.to_dict(),
        }
        if token_admin:
            try:
                admin_result = http_client.get(endpoint, headers=auth_headers(token_admin))
                row["admin_status"] = admin_result.status_code
                row["admin_size"] = admin_result.size
            except Exception:
                row["admin_status"] = "error"
        matrix.append(row)
        if score_data.score >= 5:
            findings.append(
                Finding(
                    title="Candidat IDOR/BOLA a verifier",
                    severity="medium" if score_data.score >= 7 else "low",
                    endpoint=endpoint,
                    description="Deux contextes utilisateurs autorises ont ete compares en lecture seule.",
                    proof=f"A={result_a.status_code}/{result_a.size}, B={result_b.status_code}/{result_b.size}, similarity={round(similarity, 3)}",
                    curl_command=result_a.curl_command,
                    score=score_data.score,
                    category=score_data.category,
                    confidence=score_data.confidence,
                    reason=score_data.reason,
                    evidence=score_data.evidence,
                    next_step=score_data.next_step,
                    tags=["idor", "bola"],
                )
            )

    storage.write_json("idor_matrix.json", matrix)
    storage.write_text("idor_matrix.md", render_matrix_markdown(matrix))
    storage.save_findings(findings)
    return findings


def render_matrix_markdown(matrix: list[dict]) -> str:
    lines = ["# RAVEN IDOR/BOLA Matrix", "", "| Endpoint | A | B | Similarity | Score | Notes |", "| --- | --- | --- | --- | --- | --- |"]
    for row in matrix:
        if row.get("skipped"):
            lines.append(f"| {row['endpoint']} | - | - | - | 0 | {row['skipped']} |")
            continue
        score = row.get("score", {}).get("score", 0)
        notes = row.get("score", {}).get("reason", row.get("note", ""))
        lines.append(
            f"| {row.get('endpoint', '')} | {row.get('user_a_status', '-')} | {row.get('user_b_status', '-')} | {row.get('similarity', '-')} | {score} | {notes} |"
        )
    return "\n".join(lines) + "\n"
