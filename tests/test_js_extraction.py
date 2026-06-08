from modules.js_analyzer import endpoint_criticality, extract_js_endpoints


def test_extract_js_endpoints_from_fetch_axios_xhr_and_ajax():
    body = """
    fetch('/api/users?search=test', {method: 'POST'})
    axios.get('/v1/orders')
    xhr.open('DELETE', '/api/admin/item')
    $.ajax({url: '/graphql', method: 'POST'})
    window.API_URL = '/api/profile'
    """

    rows = extract_js_endpoints(body, "https://example.com/app.js")
    pairs = {(row["method"], row["url"]) for row in rows}

    assert ("POST", "https://example.com/api/users?search=test") in pairs
    assert ("GET", "https://example.com/v1/orders") in pairs
    assert ("DELETE", "https://example.com/api/admin/item") in pairs
    assert ("POST", "https://example.com/graphql") in pairs
    assert any(row["criticality"] == "high" for row in rows)


def test_endpoint_criticality_marks_assets_as_info():
    assert endpoint_criticality("https://example.com/static/app.js") == "info"
    assert endpoint_criticality("https://example.com/api/payment") == "high"
