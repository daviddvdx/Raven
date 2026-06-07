from core.scoring import score_endpoint, score_idor, score_xss
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
