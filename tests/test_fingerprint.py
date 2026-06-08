from core.fingerprint import fingerprint_body, fingerprints_equal, similarity


def test_fingerprint_compares_hash_length_and_status():
    first = fingerprint_body("hello", 200, "text/plain")
    second = fingerprint_body("hello", 200, "text/plain")
    third = fingerprint_body("hello!", 200, "text/plain")

    assert fingerprints_equal(first, second) is True
    assert fingerprints_equal(first, third) is False
    assert first.size == 5


def test_similarity_detects_near_duplicate_custom_404():
    assert similarity("not found custom page abc", "not found custom page xyz") > 0.8
