import json

from core.config import load_settings, normalize_profile, validate_settings
from core.deduplicator import Deduplicator, normalize_url_for_dedup
from core.fingerprint import fingerprint_body, fingerprints_equal, similarity
from core.storage import Storage
from core.utils import mask_secret
from modules.content_discovery import is_filtered
from modules.secrets_scanner import find_potential_secrets


def test_profile_aliases_keep_safe_noise_profiles():
    assert normalize_profile("passive") == "quiet"
    assert normalize_profile("active-safe") == "balanced"
    assert normalize_profile("unknown") == "quiet"


def test_load_settings_validates_conservative_defaults(tmp_path):
    settings_file = tmp_path / "settings.yaml"
    settings_file.write_text(
        """
user_agent: "RAVEN test"
safe_mode: true
rate_limit_per_second: 1
max_concurrency: 2
profiles:
  passive:
    modules: [recon, js]
""",
        encoding="utf-8",
    )
    settings = load_settings(settings_file)

    assert settings.headers["User-Agent"] == "RAVEN test"
    assert settings.profile("passive")["modules"] == ["recon", "js"]
    assert validate_settings(settings) == []


def test_fingerprint_equality_and_similarity():
    first = fingerprint_body("<title>OK</title>hello", 200, "text/html")
    second = fingerprint_body("<title>OK</title>hello", 200, "text/html")
    third = fingerprint_body("completely different", 404, "text/plain")

    assert fingerprints_equal(first, second) is True
    assert similarity("hello world", "hello world!") > 0.9
    assert fingerprints_equal(first, third) is False


def test_url_dedup_normalizes_query_order_and_trailing_slash():
    dedup = Deduplicator()

    assert normalize_url_for_dedup("HTTPS://Example.com/a/?b=2&a=1") == "https://example.com/a?a=1&b=2"
    assert dedup.seen_url("https://example.com/a/?b=2&a=1") is False
    assert dedup.seen_url("https://example.com/a?a=1&b=2") is True


def test_secret_masking_and_scanner_never_expose_full_secret():
    secret = "AKIAABCDEFGHIJKLMNOP"
    masked = mask_secret(secret)
    findings = find_potential_secrets(f"key='{secret}'")

    assert masked.startswith("AKIA")
    assert secret not in masked
    assert findings
    assert secret not in json.dumps(findings)


def test_storage_writes_jsonl_and_sqlite(tmp_path):
    storage = Storage("core-test", base_dir=tmp_path)
    endpoint = {"url": "https://example.com/api", "type": "api"}

    storage.save_endpoint(endpoint)

    assert storage.read_jsonl("endpoints.jsonl") == [endpoint]
    assert storage.query_results("endpoints", limit=1)[0] == endpoint


def test_filtering_by_status_size_and_body_regex():
    from conftest import make_http_result

    result = make_http_result("https://example.com/missing", 404, "custom not found body")

    assert is_filtered(result, {404}, None, None, None) is True
    assert is_filtered(result, set(), result.size, None, None) is True
    assert is_filtered(result, set(), None, None, None, "custom not found") is True
