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
