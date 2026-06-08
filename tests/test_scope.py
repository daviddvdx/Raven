from core.scope import Scope


def test_wildcard_scope_allows_subdomain():
    scope = Scope(
        program="Example",
        researcher="tester",
        allowed_domains=["example.com", "*.example.com"],
        allowed_urls=[],
        deny=[],
        rate_limit={"requests_per_second": 2},
        headers={},
        proxy={"enabled": False},
    )
    assert scope.is_allowed_url("https://api.example.com/status")


def test_scope_denies_explicit_host():
    scope = Scope(
        program="Example",
        researcher="tester",
        allowed_domains=["example.com", "*.example.com"],
        allowed_urls=[],
        deny=["admin-prod.example.com"],
        rate_limit={"requests_per_second": 2},
        headers={},
        proxy={"enabled": False},
    )
    assert not scope.is_allowed_url("https://admin-prod.example.com/")


def test_should_request_blocks_method_path_and_out_of_scope():
    scope = Scope(
        program="Example",
        researcher="tester",
        allowed_domains=["example.com"],
        allowed_urls=[],
        deny=[],
        rate_limit={"requests_per_second": 2},
        headers={},
        proxy={"enabled": False},
        denied_paths=["/logout"],
        allowed_methods=["GET"],
        allowed_schemes=["https"],
    )

    assert scope.should_request("GET", "https://example.com/profile")[0] is True
    assert scope.should_request("POST", "https://example.com/profile")[0] is False
    assert scope.should_request("GET", "https://example.com/logout")[0] is False
    assert scope.should_request("GET", "http://example.com/profile")[0] is False
    assert scope.should_request("GET", "https://evil.example.net/profile")[0] is False
