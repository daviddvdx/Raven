"""Explainable scoring helpers for RAVEN findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


CONFIDENCE_LOW = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH = "high"


@dataclass(slots=True)
class ScoreResult:
    score: int
    category: str
    confidence: str
    reason: str
    evidence: str
    next_step: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def clamp_score(score: int) -> int:
    return max(0, min(score, 10))


def confidence_from_score(score: int) -> str:
    if score >= 8:
        return CONFIDENCE_HIGH
    if score >= 5:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def score_endpoint(path: str, status_code: int, size: int, baseline_match: bool = False) -> ScoreResult:
    lower = path.lower()
    score = 0
    reasons: list[str] = []
    if status_code == 200:
        score += 3
        reasons.append("status 200")
    if status_code in {204, 301, 302, 307, 308, 401}:
        score += 2
        reasons.append(f"interesting status {status_code}")
    if any(token in lower for token in ("/api", "/v1/", "/v2/")):
        score += 3
        reasons.append("API-like path")
    if any(lower.endswith(ext) for ext in (".env", ".bak", ".old", ".zip", ".config", ".yml", ".yaml", ".json")):
        score += 4
        reasons.append("sensitive file extension")
    if baseline_match:
        score -= 4
        reasons.append("matches baseline noise")
    score = clamp_score(score)
    return ScoreResult(
        score=score,
        category="endpoint",
        confidence=confidence_from_score(score),
        reason=", ".join(reasons) or "low-signal endpoint",
        evidence=f"status={status_code} size={size}",
        next_step="Verify exposure and expected authentication manually in Burp Suite.",
    )


def score_idor(signals: dict[str, Any]) -> ScoreResult:
    score = 0
    reasons: list[str] = []
    if signals.get("both_200_same_object"):
        score += 5
        reasons.append("both user contexts receive 200 for the same object candidate")
    if signals.get("low_privilege_admin_200"):
        score += 4
        reasons.append("low privilege user receives 200 on admin/internal/private endpoint")
    if signals.get("expected_forbidden_but_200"):
        score += 3
        reasons.append("200 observed where forbidden behavior may be expected")
    if signals.get("path_identifier"):
        score += 3
        reasons.append("numeric ID, UUID, or global ID in path")
    if signals.get("interesting_param"):
        score += 2
        reasons.append("interesting ownership parameter")
    if signals.get("sensitive_object_action"):
        score += 5
        reasons.append("download/export/invoice/document/file endpoint")
    if signals.get("generic_error"):
        score -= 4
        reasons.append("response resembles generic error")
    if signals.get("out_of_scope"):
        score -= 3
        reasons.append("endpoint out of scope")
    if signals.get("state_changing"):
        score -= 2
        reasons.append("state-changing action requires explicit authorization")
    score = clamp_score(score)
    return ScoreResult(
        score=score,
        category="idor",
        confidence=confidence_from_score(score),
        reason=", ".join(reasons) or "weak IDOR/BOLA signal",
        evidence=str(signals),
        next_step="Verify object ownership manually with authorized accounts in Burp Suite.",
    )


def score_xss(signals: dict[str, Any]) -> ScoreResult:
    score = 0
    reasons: list[str] = []
    if signals.get("interesting_param"):
        score += 2
        reasons.append("interesting reflected-input parameter")
    if signals.get("reflected"):
        score += 3
        reasons.append("safe probe reflected")
    if signals.get("html_attribute"):
        score += 4
        reasons.append("reflection in HTML attribute")
    if signals.get("script_context"):
        score += 5
        reasons.append("reflection in script context")
    if signals.get("unencoded"):
        score += 3
        reasons.append("probe appears visibly unencoded")
    if signals.get("public_endpoint"):
        score += 2
        reasons.append("endpoint appears publicly reachable")
    if signals.get("encoded"):
        score -= 3
        reasons.append("reflection appears encoded")
    if not signals.get("reflected"):
        score -= 4
        reasons.append("no reflection")
    if signals.get("safe_json"):
        score -= 2
        reasons.append("JSON response appears safely escaped")
    score = clamp_score(score)
    return ScoreResult(
        score=score,
        category="xss",
        confidence=confidence_from_score(score),
        reason=", ".join(reasons) or "weak XSS reflection signal",
        evidence=str(signals),
        next_step="Validate context manually in Burp Suite without executing browser-side payloads.",
    )


def score_exploitdb_match(finding: dict[str, Any], matches: dict[str, Any]) -> ScoreResult:
    score = 0
    reasons: list[str] = []
    technology = finding.get("technology") or matches.get("technology")
    vuln_class = finding.get("vulnerability_class") or matches.get("vulnerability_class")
    cves = matches.get("cves", []) or finding.get("cves", [])
    exploitdb_matches = int(matches.get("exploitdb_matches", matches.get("matches_count", 0)) or 0)
    version_exact = bool(matches.get("version_exact"))
    version_unknown = bool(matches.get("version_unknown", not version_exact and technology))
    endpoint_compatible = bool(matches.get("endpoint_compatible"))
    param_match = bool(matches.get("param_match"))
    sensitive_pattern = bool(matches.get("sensitive_pattern"))
    quiet_penalty = bool(matches.get("quiet_dangerous_penalty"))
    nominal_only = bool(matches.get("nominal_only"))
    active_not_allowed = bool(matches.get("active_validation_not_allowed"))

    if version_exact and exploitdb_matches:
        score += 6
        reasons.append("technology and exact version correlate with Exploit-DB metadata")
    elif version_unknown and exploitdb_matches:
        score += 4
        reasons.append("technology correlates with Exploit-DB metadata but version is unknown")
    if cves:
        score += 5
        reasons.append("CVE appears in local Exploit-DB metadata")
    if vuln_class and endpoint_compatible:
        score += 3
        reasons.append("historical vulnerability class is compatible with the endpoint")
    if param_match:
        score += 2
        reasons.append("endpoint parameter matches Exploit-DB-inspired safe pattern")
    if sensitive_pattern:
        score += 3
        reasons.append("endpoint contains a sensitive path/action associated with historical reports")
    if quiet_penalty:
        score -= 5
        reasons.append("DoS/shellcode/local exploit filtered or downranked in quiet profile")
    if matches.get("out_of_scope_technology"):
        score -= 4
        reasons.append("technology signal is outside current scope context")
    if nominal_only:
        score -= 3
        reasons.append("nominal match only; no version or endpoint evidence")
    if active_not_allowed:
        score -= 5
        reasons.append("active validation is not authorized")

    score = clamp_score(score)
    evidence = {
        "technology": technology,
        "exploitdb_matches": exploitdb_matches,
        "cves": cves,
        "vulnerability_class": vuln_class,
        "matched_patterns": matches.get("matched_patterns", []),
    }
    category = "cve_match" if cves else "known_vulnerable_technology" if technology else "exploit_pattern"
    return ScoreResult(
        score=score,
        category=category,
        confidence=confidence_from_score(score),
        reason=", ".join(reasons) or "weak Exploit-DB metadata correlation",
        evidence=str(evidence),
        next_step="Verify exact version, affected route, and authorization behavior manually; do not execute PoCs.",
    )
