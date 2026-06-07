import json

from modules.xss_reflection_checker import build_probe_urls, detect_reflection_context, load_payloads, run_xss_reflection


def test_build_probe_urls_uses_fuzz_marker():
    urls = build_probe_urls("https://example.com/search?q=FUZZ", ["ravenxss"], {"q"})
    assert urls[0][0] == "https://example.com/search?q=ravenxss"


def test_reflection_context_detects_attribute():
    context = detect_reflection_context('<input value="ravenxss">', "ravenxss", "text/html")
    assert context["reflected"] is True
    assert context["html_attribute"] is True


def test_safe_payloads_do_not_load_custom_automatically(tmp_path):
    payload_file = tmp_path / "payloads.txt"
    payload_file.write_text("<script>alert(1)</script>\n", encoding="utf-8")
    payloads = load_payloads(str(payload_file), max_payloads=5, safe_only=True)
    assert "<script>alert(1)</script>" not in payloads


def test_run_xss_reflection_records_out_of_scope_without_request(context_factory):
    from conftest import StaticHTTPClient

    client = StaticHTTPClient()
    context = context_factory(target="https://evil.example.net/search?q=FUZZ", http_client=client)
    findings = run_xss_reflection(context, max_payloads=1)

    assert findings == []
    assert client.calls == []
    rows = json.loads(context["storage"].path("xss_reflections.json").read_text(encoding="utf-8"))
    assert rows[0]["skipped"] == "out_of_scope"


def test_run_xss_reflection_finds_attribute_reflection_safely(context_factory):
    from conftest import StaticHTTPClient, make_http_result

    url = "https://example.com/search?q=ravenxss"
    client = StaticHTTPClient(
        routes={
            url: make_http_result(
                url,
                200,
                '<html><body><input value="ravenxss"></body></html>',
                "text/html",
            )
        }
    )
    context = context_factory(target="https://example.com/search?q=FUZZ", http_client=client)
    findings = run_xss_reflection(context, max_payloads=1, safe_only=True)

    assert len(findings) == 1
    assert findings[0].category == "xss"
    assert "Aucune execution navigateur" in findings[0].description
    assert all("<script>" not in call["url"] for call in client.calls)


def test_json_escaped_reflection_is_not_reported_as_finding(context_factory):
    from conftest import StaticHTTPClient, make_http_result

    url = "https://example.com/search?q=%3Cravenxss%3E"
    client = StaticHTTPClient(
        routes={
            url: make_http_result(
                url,
                200,
                '{"q":"&lt;ravenxss&gt;"}',
                "application/json",
            )
        }
    )
    context = context_factory(target="https://example.com/search?q=FUZZ", http_client=client)
    findings = run_xss_reflection(context, max_payloads=3, safe_only=True)

    assert findings == []
