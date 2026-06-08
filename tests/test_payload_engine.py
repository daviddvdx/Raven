from core.scope import Scope
from modules.active_payloads import PayloadEngine


def test_payload_engine_generates_safe_marker_payloads():
    scope = Scope("Test", "tester", ["example.com"], [], [], {}, {}, {"enabled": False})
    engine = PayloadEngine(http_client=None, scope=scope)

    payloads = engine.payloads_for_param("q")

    assert any("raven-marker" in payload for payload in payloads)
    assert all("alert(" not in payload.lower() for payload in payloads)


def test_payload_engine_detects_safe_reflection_without_script(context_factory):
    from conftest import StaticHTTPClient, make_http_result

    class ReflectClient(StaticHTTPClient):
        def safe_request(self, method, url, **kwargs):
            marker = url.split("q=")[-1]
            return make_http_result(url, 200, f"<html>{marker}</html>")

    context = context_factory("https://example.com/search?q=base", ReflectClient())
    engine = PayloadEngine(context["http_client"], context["scope"], context["storage"], max_payloads_per_param=1)

    findings = engine.scan_endpoint({"url": "https://example.com/search?q=base", "method": "GET"})

    assert findings
    assert findings[0].title == "Safe reflection detected"
    assert "alert(" not in findings[0].proof.lower()
