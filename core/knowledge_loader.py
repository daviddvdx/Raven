"""Local knowledge loading for report patterns and safe payload references."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PAYLOADS_ALL_THE_THINGS_PATHS = [
    "/usr/share/payloadsallthethings",
    "/opt/PayloadsAllTheThings",
]


class KnowledgeLoader:
    def __init__(self, knowledge_dir: str | Path = "knowledge") -> None:
        self.knowledge_dir = Path(knowledge_dir)

    def load_report_patterns(self) -> dict[str, Any]:
        return self._load_yaml("report_patterns.yaml")

    def load_exploitdb_patterns(self) -> dict[str, Any]:
        return self._load_yaml("exploitdb_patterns.yaml")

    def get_vulnerability_keywords(self) -> dict[str, list[str]]:
        patterns = self.load_exploitdb_patterns()
        classes = patterns.get("vulnerability_classes", {})
        return {name: data.get("title_keywords", []) for name, data in classes.items()}

    def get_technology_aliases(self) -> dict[str, list[str]]:
        patterns = self.load_exploitdb_patterns()
        return patterns.get("technology_aliases", {})

    def get_safe_patterns_for_class(self, vuln_class: str) -> dict[str, Any]:
        patterns = self.load_exploitdb_patterns()
        return patterns.get("vulnerability_classes", {}).get(vuln_class, {})

    def load_lines(self, filename: str, limit: int | None = None) -> list[str]:
        path = self.knowledge_dir / filename
        if not path.exists():
            return []
        lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.startswith("#")]
        return lines[:limit] if limit else lines

    def detect_payloads_all_the_things(self) -> Path | None:
        for candidate in PAYLOADS_ALL_THE_THINGS_PATHS:
            path = Path(candidate)
            if path.exists() and path.is_dir():
                return path
        return None

    def load_payload_file(self, payload_file: str | None, max_payloads: int = 5) -> list[str]:
        if not payload_file:
            return []
        path = Path(payload_file)
        if not path.exists():
            return []
        lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
        return lines[: max(0, max_payloads)]

    def _load_yaml(self, filename: str) -> dict[str, Any]:
        path = self.knowledge_dir / filename
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
