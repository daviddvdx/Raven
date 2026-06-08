from main import collect_saved_endpoints


def test_collect_saved_endpoints_deduplicates_and_limits(context_factory):
    context = context_factory("https://example.com")
    storage = context["storage"]
    for _index in range(2):
        storage.save_endpoint({"url": "https://example.com/api/users?q=1", "method": "GET", "type": "api"})
    storage.save_endpoint({"url": "https://example.com/api/users", "method": "POST", "type": "api"})

    rows = collect_saved_endpoints(context)

    assert rows == [
        {"url": "https://example.com/api/users?q=1", "method": "GET", "type": "api"},
        {"url": "https://example.com/api/users", "method": "POST", "type": "api"},
    ]


def test_collect_saved_endpoints_falls_back_to_target(context_factory):
    context = context_factory("https://example.com")

    rows = collect_saved_endpoints(context)

    assert rows[0]["url"] == "https://example.com"
    assert rows[0]["method"] == "GET"
