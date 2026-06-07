"""Professional terminal identity for RAVEN."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rich.console import Console
from rich.table import Table

APP_NAME = "RAVEN"
VERSION = "0.1.0-dev"
DESCRIPTION = "Reconnaissance & API Vulnerability Enumeration Navigator"

console = Console()

ASCII_BANNER = r"""
██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
"""


def print_banner(mode: str | None = None) -> None:
    console.print(ASCII_BANNER, style="bold cyan")
    console.print(f"        [bold]{DESCRIPTION}[/bold]")
    console.print(f"        [dim]v{VERSION}[/dim]\n")
    console.rule(style="dim")
    if mode:
        console.print(f"[dim]:: Mode[/dim]              : [bold]{mode.upper()}[/bold]")


def print_run_config(config: Mapping[str, Any]) -> None:
    table = Table.grid(padding=(0, 1))
    table.add_column(style="dim", justify="right")
    table.add_column(style="white")
    for key, value in config.items():
        if value is None or value == "":
            continue
        rendered = ", ".join(str(item) for item in value) if isinstance(value, (list, tuple, set)) else str(value)
        table.add_row(f":: {key}", f": {rendered}")
    console.print(table)
    console.rule(style="dim")
    console.print()


def print_section(title: str) -> None:
    console.rule(f"[bold cyan]{title}[/bold cyan]", style="dim")


def print_success(message: str) -> None:
    console.print(f"[green][+][/green] {message}")


def print_warning(message: str) -> None:
    console.print(f"[yellow][!][/yellow] {message}")


def print_error(message: str) -> None:
    console.print(f"[red][-][/red] {message}")


def print_finding(status: int, url: str, size: int = 0, words: int = 0, lines: int = 0, score: int = 0, title: str | None = None) -> None:
    if status in {200, 204}:
        style = "green"
    elif status in {301, 302, 307, 308, 401, 403}:
        style = "yellow"
    elif status >= 500:
        style = "red"
    else:
        style = "cyan"
    meta = f"size={size} words={words} lines={lines} score={score}"
    suffix = f" title={title}" if title else ""
    console.print(f"[{style}][{status}][/{style}] {url} [dim]{meta}{suffix}[/dim]")
