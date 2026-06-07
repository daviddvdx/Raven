from pathlib import Path

from core.wordlist_manager import WordlistManager


def test_wordlist_manager_detects_seclists(tmp_path):
    seclists = tmp_path / "SecLists"
    wordlist = seclists / "Discovery" / "Web-Content" / "common.txt"
    wordlist.parent.mkdir(parents=True)
    wordlist.write_text("admin\n", encoding="utf-8")
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
seclists:
  base_paths:
    - "{seclists.as_posix()}"
wordlist_profiles:
  quiet:
    web_content:
      - "Discovery/Web-Content/common.txt"
""",
        encoding="utf-8",
    )
    manager = WordlistManager(settings)
    status = manager.status("quiet", "web_content")
    assert status.seclists_detected is True
    assert str(wordlist) in status.existing


def test_wordlist_manager_uses_local_fallback(tmp_path):
    settings = tmp_path / "settings.yaml"
    settings.write_text("seclists:\n  base_paths: []\n", encoding="utf-8")
    manager = WordlistManager(settings)
    selected = manager.select_wordlists("quiet", "web_content")
    assert [Path(item).as_posix() for item in selected] == ["wordlists/small.txt"]


def test_deep_profile_is_not_used_without_confirmation(tmp_path):
    settings = tmp_path / "settings.yaml"
    settings.write_text("seclists:\n  base_paths: []\n", encoding="utf-8")
    manager = WordlistManager(settings)
    selected = manager.select_wordlists("deep", "api", allow_deep=False)
    assert [Path(item).as_posix() for item in selected] == ["wordlists/api.txt"]


def test_status_reports_existing_and_missing_profile_entries(tmp_path):
    seclists = tmp_path / "seclists"
    existing = seclists / "Discovery" / "Web-Content" / "common.txt"
    existing.parent.mkdir(parents=True)
    existing.write_text("admin\n", encoding="utf-8")
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"""
seclists:
  base_paths:
    - "{seclists.as_posix()}"
wordlist_profiles:
  quiet:
    web_content:
      - "Discovery/Web-Content/common.txt"
      - "Discovery/Web-Content/missing.txt"
""",
        encoding="utf-8",
    )

    status = WordlistManager(settings).status("quiet", "web_content")

    assert status.existing == [str(existing)]
    assert status.missing == ["Discovery/Web-Content/missing.txt"]
    assert status.selected == [str(existing)]
