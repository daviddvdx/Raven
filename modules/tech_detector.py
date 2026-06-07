"""Technology detection facade."""

from __future__ import annotations

from typing import Any

from core.exploitdb_manager import ExploitDBManager
from core.scoring import score_exploitdb_match
from core.utils import detect_technologies


def enrich_with_exploitdb(fingerprint: dict[str, Any], profile: str = "quiet") -> dict[str, Any]:
    manager = ExploitDBManager(profile=profile, metadata_only=True)
    matches = manager.match_fingerprint(fingerprint)
    score = score_exploitdb_match(
        {"technology": ", ".join(fingerprint.get("technologies", [])), "vulnerability_class": fingerprint.get("vulnerability_class")},
        {
            "technology": ", ".join(fingerprint.get("technologies", [])),
            "exploitdb_matches": matches.get("matches_count", 0),
            "cves": list(matches.get("cves", {}).keys()),
            "version_unknown": bool(matches.get("matches_count", 0)),
            "nominal_only": not fingerprint.get("version"),
            "matched_patterns": list(matches.get("technologies", {}).keys()),
        },
    )
    return {
        "technologies": fingerprint.get("technologies", []),
        "exploitdb_matches": matches,
        "score": score.to_dict(),
        "next_step": "Verify product version and affected endpoints manually; do not execute Exploit-DB PoCs.",
    }


__all__ = ["detect_technologies", "enrich_with_exploitdb"]
