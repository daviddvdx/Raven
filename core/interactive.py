"""Interactive terminal prompts for RAVEN workflows."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rich.console import Console
from rich.table import Table

YES_VALUES = {"y", "yes", "o", "oui"}
NO_VALUES = {"n", "no", "non"}
STRONG_CONFIRMATION = "I UNDERSTAND THE RISK"


class InteractiveSession:
    def __init__(self, settings: dict[str, Any] | None = None, project_config: dict[str, Any] | None = None, input_func: Callable[[str], str] | None = None) -> None:
        self.settings = settings or {}
        self.project_config = project_config or {}
        self.input_func = input_func or input
        self.console = Console()
        self.decisions: dict[str, Any] = {}

    def ask_yes_no(self, question: str, default: bool = False) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            raw = self._ask(f"[?] {question} {hint}: ").strip().lower()
            if not raw:
                return default
            if raw in YES_VALUES:
                return True
            if raw in NO_VALUES:
                return False
            self.console.print("[yellow]Please answer y/yes/o/oui or n/no/non.[/yellow]")

    def ask_choice(self, question: str, choices: list[str], default: str | None = None) -> str:
        normalized = {choice.lower(): choice for choice in choices}
        suffix = f"[{'/'.join(choices)}]"
        if default:
            suffix += f" ({default})"
        while True:
            raw = self._ask(f"[?] {question} {suffix}: ").strip()
            if not raw and default:
                return default
            value = normalized.get(raw.lower())
            if value:
                return value
            self.console.print(f"[yellow]Choose one of: {', '.join(choices)}[/yellow]")

    def ask_int(self, question: str, min_value: int = 1, max_value: int = 10, default: int = 3) -> int:
        while True:
            raw = self._ask(f"[?] {question} {min_value}-{max_value} [{default}]: ").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                self.console.print("[yellow]Please enter a number.[/yellow]")
                continue
            if min_value <= value <= max_value:
                return value
            self.console.print(f"[yellow]Value must be between {min_value} and {max_value}.[/yellow]")

    def ask_text(self, question: str, default: str | None = None, required: bool = False) -> str:
        suffix = f" ({default})" if default else ""
        while True:
            raw = self._ask(f"[?] {question}{suffix}: ").strip()
            if raw:
                return raw
            if default is not None:
                return default
            if not required:
                return ""
            self.console.print("[yellow]This value is required.[/yellow]")

    def confirm_step(self, step_name: str, description: str | None = None, default: bool = False) -> bool:
        self.print_step_banner(step_name)
        if description:
            self.console.print(f"[dim]{description}[/dim]")
        decision = self.ask_yes_no("Launch?", default=default)
        self.decisions[step_name] = decision
        return decision

    def ask_noise_level(self, default: int = 3) -> int:
        value = self.ask_int("Niveau de bruit", 1, 10, default)
        self.decisions["noise_level"] = value
        return value

    def ask_scan_profile(self, default: str = "quiet") -> str:
        value = self.ask_choice("Profil de scan", ["quiet", "balanced", "deep"], default)
        self.decisions["profile"] = value
        return value

    def ask_filters(self) -> dict:
        ignore_status = []
        if self.ask_yes_no("Ignorer les 404 ?", default=True):
            ignore_status.append(404)
        if self.ask_yes_no("Ignorer les 403 ?", default=True):
            ignore_status.append(403)
        filters = {
            "ignore_status": ignore_status,
            "auto_filter_repeated_sizes": self.ask_yes_no("Ignorer tailles recurrentes ?", default=True),
            "auto_filter_repeated_words": self.ask_yes_no("Ignorer mots recurrents ?", default=True),
            "auto_filter_repeated_lines": self.ask_yes_no("Ignorer lignes recurrentes ?", default=True),
            "continue_if_waf_detected": self.ask_yes_no("Continuer si WAF detecte ?", default=False),
        }
        self.decisions["filters"] = filters
        return filters

    def ask_rate_limit(self, default_rate: int = 10) -> dict:
        rate = self.ask_int("Rate limit req/s", 1, 20, default_rate)
        threads = self.ask_int("Threads", 1, 10, 3)
        config = {"rate": rate, "threads": threads}
        self.decisions["rate_limit"] = config
        return config

    def ask_state_changing_permission(self) -> bool:
        allowed = self.ask_yes_no("Allow state-changing methods?", default=False)
        self.decisions["allow_state_changing"] = allowed
        return allowed

    def ask_save_decisions(self) -> bool:
        value = self.ask_yes_no("Save this workflow for this project?", default=True)
        self.decisions["save_decisions"] = value
        return value

    def ask_strong_confirmation(self) -> bool:
        raw = self.ask_text(f'Type exactly "{STRONG_CONFIRMATION}" to continue', required=False)
        return raw == STRONG_CONFIRMATION

    def print_step_banner(self, step_name: str) -> None:
        self.console.rule(f"[bold cyan]{step_name}[/bold cyan]", style="dim")

    def print_decision_summary(self, decisions: dict) -> None:
        table = Table(title="Final summary")
        table.add_column("Step")
        table.add_column("Decision")
        for key, value in decisions.items():
            table.add_row(str(key), "yes" if value is True else "no" if value is False else str(value))
        self.console.print(table)

    def _ask(self, prompt: str) -> str:
        try:
            return self.input_func(prompt)
        except (EOFError, KeyboardInterrupt):
            return ""
