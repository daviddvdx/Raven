"""Project result storage for RAVEN."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from core.models import Finding, HTTPResult


class Storage:
    def __init__(self, project: str, base_dir: str | Path = "results") -> None:
        self.project = project
        self.root = Path(base_dir) / project
        self.raw_dir = self.root / "raw"
        self.js_files_dir = self.root / "js_files"
        self.screenshots_dir = self.root / "screenshots"
        self.reports_dir = self.root / "reports"
        for directory in (self.root, self.raw_dir, self.js_files_dir, self.screenshots_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self.sqlite_path = self.root / "raven.sqlite3"
        self._init_sqlite()

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
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(data, ensure_ascii=False) + "\n")

    def read_jsonl(self, name: str) -> list[dict[str, Any]]:
        path = self.path(name)
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    def save_http_result(self, name: str, result: HTTPResult) -> None:
        self.append_jsonl(name, result.to_dict())
        self.insert_result("http_results", result.to_dict())

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
        for finding in findings:
            finding_data = finding.to_dict()
            self.append_jsonl("findings.jsonl", finding_data)
            self.insert_result("findings", finding_data)
        return self.write_json("findings.json", existing)

    def insert_result(self, table: str, data: dict[str, Any]) -> None:
        if table not in {"findings", "http_results", "endpoints"}:
            raise ValueError(f"Unsupported table: {table}")
        with sqlite3.connect(self.sqlite_path) as conn:
            conn.execute(
                f"INSERT INTO {table} (project, data) VALUES (?, ?)",
                (self.project, json.dumps(data, ensure_ascii=False)),
            )

    def save_endpoint(self, endpoint: dict[str, Any]) -> None:
        self.append_jsonl("endpoints.jsonl", endpoint)
        self.insert_result("endpoints", endpoint)

    def query_results(self, table: str, limit: int = 100) -> list[dict[str, Any]]:
        if table not in {"findings", "http_results", "endpoints"}:
            raise ValueError(f"Unsupported table: {table}")
        with sqlite3.connect(self.sqlite_path) as conn:
            rows = conn.execute(f"SELECT data FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        output = []
        for (raw,) in rows:
            try:
                output.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return output

    def _init_sqlite(self) -> None:
        with sqlite3.connect(self.sqlite_path) as conn:
            for table in ("findings", "http_results", "endpoints"):
                conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {table} (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project TEXT NOT NULL,
                        data TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
