import json

import pytest

from modules.idor_helper import detect_graphql_global_id, endpoint_signals, requires_two_authorized_tokens, run_idor


def test_endpoint_signals_detect_id_param():
    patterns = {"idor_bola": {"interesting_params": ["user_id"], "risky_actions": ["delete"]}}
    signals = endpoint_signals("https://example.com/api/users?user_id=123", patterns)
    assert signals["interesting_param"] is True


def test_endpoint_signals_detects_path_identifier():
    patterns = {"idor_bola": {"interesting_params": [], "risky_actions": []}}
    signals = endpoint_signals("https://example.com/api/documents/12345", patterns)
    assert signals["path_identifier"] is True


def test_graphql_global_id_detection():
    assert detect_graphql_global_id("VXNlcjoxMjM=") is True


def test_requires_two_tokens_before_any_idor_comparison():
    with pytest.raises(ValueError):
        requires_two_authorized_tokens("TOKEN_A", "")


def test_run_idor_skips_out_of_scope_without_request(tmp_path, context_factory):
    from conftest import StaticHTTPClient

    endpoints = tmp_path / "endpoints.txt"
    endpoints.write_text("https://evil.example.net/api/users/123\n", encoding="utf-8")
    client = StaticHTTPClient()
    context = context_factory(target="https://example.com", http_client=client)

    findings = run_idor(context, str(endpoints), "TOKEN_A", "TOKEN_B")

    assert findings == []
    assert client.calls == []
    matrix = json.loads(context["storage"].path("idor_matrix.json").read_text(encoding="utf-8"))
    assert matrix[0]["skipped"] == "out_of_scope"


def test_run_idor_compares_only_get_with_authorized_tokens(tmp_path, context_factory):
    from conftest import StaticHTTPClient, make_http_result

    endpoint = "https://example.com/api/documents/123"
    endpoints = tmp_path / "endpoints.txt"
    endpoints.write_text(f"{endpoint}\n", encoding="utf-8")
    body = '{"id":123,"owner":"user-a","document":"invoice.pdf"}'
    client = StaticHTTPClient(routes={endpoint: make_http_result(endpoint, 200, body, "application/json")})
    context = context_factory(target="https://example.com", http_client=client)

    findings = run_idor(context, str(endpoints), "TOKEN_A", "TOKEN_B")

    assert len(client.calls) == 2
    assert {call["headers"]["Authorization"] for call in client.calls} == {"Bearer TOKEN_A", "Bearer TOKEN_B"}
    assert findings
    assert findings[0].category == "idor"
    matrix = json.loads(context["storage"].path("idor_matrix.json").read_text(encoding="utf-8"))
    assert matrix[0]["signals"]["path_identifier"] is True
    assert matrix[0]["score"]["score"] >= 5
