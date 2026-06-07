from modules.idor_helper import detect_graphql_global_id, endpoint_signals


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
