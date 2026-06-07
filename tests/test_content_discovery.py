import json

from modules.content_discovery import build_candidates, fuzz, matches_baseline


def test_build_candidates_applies_extensions_without_duplicates():
    candidates = build_candidates("https://example.com/FUZZ", ["admin", "app.js"], [".js", ".json"])

    assert "https://example.com/admin" in candidates
    assert "https://example.com/admin.js" in candidates
    assert "https://example.com/admin.json" in candidates
    assert candidates.count("https://example.com/app.js") == 1


def test_matches_baseline_on_hash_even_when_size_differs():
    from conftest import make_http_result

    result = make_http_result("https://example.com/random", 404, "same generic 404")
    baseline = [{"status_code": 404, "size": result.size + 10, "words": result.words, "body_hash": result.body_hash}]

    assert matches_baseline(result, baseline) is True


def test_fuzz_filters_calibration_noise_and_keeps_real_finding(tmp_path, context_factory):
    from conftest import StaticHTTPClient, make_http_result

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nmissing\n", encoding="utf-8")
    admin_url = "https://example.com/admin"
    missing_url = "https://example.com/missing"
    client = StaticHTTPClient(
        routes={
            admin_url: make_http_result(admin_url, 200, "<title>Admin</title>admin panel"),
            missing_url: make_http_result(missing_url, 404, "generic not found"),
        },
        default=make_http_result("https://example.com/random", 404, "generic not found"),
    )
    context = context_factory(target="https://example.com/FUZZ", http_client=client)

    findings = fuzz(
        context,
        wordlist=str(wordlist),
        extensions=[],
        matcher_status={200, 404},
        filter_status=set(),
        calibrate=True,
        threads=1,
    )

    assert [finding.endpoint for finding in findings] == [admin_url]
    filtered = json.loads(context["storage"].path("filtered_noise.json").read_text(encoding="utf-8"))
    assert any(row["reason"] == "matched calibration baseline" for row in filtered)
    baselines = json.loads(context["storage"].path("baselines/fuzz_baseline.json").read_text(encoding="utf-8"))
    assert len(baselines) >= 3
