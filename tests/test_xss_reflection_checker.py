from modules.xss_reflection_checker import build_probe_urls, detect_reflection_context, load_payloads


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
