from core.deduplicator import Deduplicator, normalize_url_for_dedup


def test_deduplicator_normalizes_case_query_and_trailing_slash():
    assert normalize_url_for_dedup("HTTPS://Example.COM/a/?z=1&a=2") == "https://example.com/a?a=2&z=1"


def test_deduplicator_tracks_urls_and_body_hashes():
    dedup = Deduplicator()

    assert dedup.seen_url("https://example.com/a/?z=1&a=2") is False
    assert dedup.seen_url("https://example.com/a?a=2&z=1") is True
    assert dedup.seen_body_hash("abc") is False
    assert dedup.seen_body_hash("abc") is True
