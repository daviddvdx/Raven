"""Project result storage for RAVEN."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import Finding, HTTPResult


class Storage:
    def __init__(self, project: str, base_dir: str | Path = "results") -> None:
        self.project = project
        self.root = Path(base_dir) / project
        self.raw_dir = self.root / "raw"
        self.screenshots_dir = self.root / "screenshots"
        self.reports_dir = self.root / "reports"
        for directory in (self.root, self.raw_dir, self.screenshots_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        return self.root / name

    def append_line(self, name: str, value: str) -> None:
        if not value:
            return
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = set(path.read_text(encoding="utf-8", errors="ignore").splitlines()) if path.exists() else set()
        if value not in existing:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"{value}\n")

    def write_text(self, name: str, value: str) -> Path:
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def write_json(self, name: str, data: Any) -> Path:
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def append_jsonl(self, name: str, data: dict[str, Any]) -> None:
        path = self.path(name)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(data, ensure_ascii=False) + "\n")

    def save_http_result(self, name: str, result: HTTPResult) -> None:
        self.append_jsonl(name, result.to_dict())

    def save_findings(self, findings: list[Finding]) -> Path:
        existing: list[dict[str, Any]] = []
        path = self.path("findings.json")
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = []
        existing.extend(finding.to_dict() for finding in findings)
        existing.sort(key=lambda item: item.get("score", 0), reverse=True)
        return self.write_json("findings.json", existing)
