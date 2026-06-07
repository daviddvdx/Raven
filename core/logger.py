"""Rich-backed logging helpers."""

from __future__ import annotations

from rich.console import Console


class Logger:
    def __init__(self, verbose: bool = False) -> None:
        self.console = Console()
        self.verbose = verbose

    def info(self, message: str) -> None:
        if self.verbose:
            self.console.print(f"[dim]{message}[/dim]")

    def success(self, message: str) -> None:
        self.console.print(f"[green][+][/green] {message}")

    def warning(self, message: str) -> None:
        self.console.print(f"[yellow][!][/yellow] {message}")

    def error(self, message: str) -> None:
        self.console.print(f"[red][-][/red] {message}")
