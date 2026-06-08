from core.redaction import mask_headers, mask_secret, mask_url


def test_mask_secret_hides_jwt_and_email():
    token = "eyJaaaaaaaaaaaa.bbbbbbbbbbbbb.cccccccccccc"
    email = "researcher@example.com"

    assert token not in mask_secret(token)
    assert "resear" not in mask_secret(email)
    assert "@" in mask_secret(email)


def test_mask_headers_hides_authorization_and_cookie():
    headers = mask_headers({"Authorization": "Bearer SECRET_TOKEN_VALUE", "Cookie": "sid=SECRET", "Accept": "application/json"})

    assert "SECRET_TOKEN_VALUE" not in headers["Authorization"]
    assert "SECRET" not in headers["Cookie"]
    assert headers["Accept"] == "application/json"


def test_mask_url_hides_sensitive_query_tokens():
    masked = mask_url("https://example.com/cb?access_token=abcdef1234567890&code=ok")

    assert "abcdef1234567890" not in masked
    assert "code=ok" in masked
