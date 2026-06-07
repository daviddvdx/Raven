from core.scoring import score_endpoint, score_exploitdb_match, score_idor, score_xss
from core.models import HTTPResult
from modules.content_discovery import matches_baseline


def test_endpoint_scoring_explains_sensitive_file():
    result = score_endpoint("https://example.com/.env", 200, 120)
    assert result.score >= 7
    assert result.category == "endpoint"
    assert "sensitive" in result.reason


def test_idor_scoring_for_same_object():
    result = score_idor({"both_200_same_object": True, "interesting_param": True})
    assert result.score >= 7
    assert result.category == "idor"


def test_xss_scoring_penalizes_no_reflection():
    result = score_xss({"interesting_param": True, "reflected": False})
    assert result.score <= 2
    assert result.category == "xss"


def test_baseline_filtering_matches_signature():
    result = HTTPResult(
        url="https://example.com/noise",
        method="GET",
        status_code=404,
        size=120,
        lines=3,
        words=10,
        body_hash="abc",
        title=None,
        important_headers={},
        redirect_url=None,
        response_time_ms=10,
        technologies=[],
        curl_command="curl https://example.com/noise",
    )
    baseline = [{"signature": [404, 120, 10, 3, "abc"]}]
    assert matches_baseline(result, baseline) is True


def test_exploitdb_scoring_rewards_exact_version_and_cve():
    result = score_exploitdb_match(
        {"technology": "keycloak", "vulnerability_class": "open_redirect"},
        {
            "exploitdb_matches": 2,
            "version_exact": True,
            "cves": ["CVE-2023-0000"],
            "endpoint_compatible": True,
            "matched_patterns": ["realms", "openid-connect"],
        },
    )

    assert result.score >= 10
    assert result.category == "cve_match"
    assert "exact version" in result.reason
    assert "do not execute PoCs" in result.next_step


def test_exploitdb_scoring_downranks_dangerous_nominal_quiet_match():
    result = score_exploitdb_match(
        {"technology": "example"},
        {
            "exploitdb_matches": 1,
            "version_unknown": True,
            "quiet_dangerous_penalty": True,
            "nominal_only": True,
            "active_validation_not_allowed": True,
        },
    )

    assert result.score == 0
    assert "DoS/shellcode/local exploit" in result.reason
