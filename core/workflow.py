"""Bug Bounty workflow planning and execution for RAVEN."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.interactive import InteractiveSession
from core.noise_guard import is_noise_allowed_for_yes, noise_level_config, requires_strong_confirmation_for_noise
from modules.api_analyzer import run_api
from modules.content_discovery import run_fuzz
from modules.cors_checker import run_cors
from modules.exploitdb_intelligence import run_exploitdb_intelligence
from modules.graphql_analyzer import run_graphql
from modules.js_analyzer import run_js
from modules.oauth_checker import run_oauth
from modules.recon import run_recon
from modules.report_generator import generate_report
from modules.xss_reflection_checker import run_xss_reflection


@dataclass(slots=True)
class WorkflowStep:
    name: str
    description: str
    module_name: str
    enabled_by_default: bool = False
    requires_auth: bool = False
    requires_tokens: bool = False
    can_be_noisy: bool = False
    can_change_state: bool = False
    recommended_profile: str = "quiet"
    risk_level: str = "low"


@dataclass(slots=True)
class WorkflowPlan:
    steps: list[WorkflowStep]
    selected_steps: dict[str, bool] = field(default_factory=dict)
    global_profile: str = "quiet"
    noise_level: int = 3
    filters: dict[str, Any] = field(default_factory=dict)
    rate_limit: dict[str, Any] = field(default_factory=dict)
    allow_post: bool = False
    allow_state_changing: bool = False
    save_decisions: bool = True
    dry_run: bool = False
    skipped_reasons: dict[str, str] = field(default_factory=dict)
    strong_confirmations: dict[str, bool] = field(default_factory=dict)

    def to_dict(self, project: str | None = None) -> dict[str, Any]:
        return {
            "project": project,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "profile": self.global_profile,
            "noise_level": self.noise_level,
            "filters": self.filters,
            "rate_limit": self.rate_limit,
            "steps": dict(self.selected_steps),
            "safety": {"allow_post": self.allow_post, "allow_state_changing": self.allow_state_changing},
            "dry_run": self.dry_run,
            "skipped_reasons": self.skipped_reasons,
            "strong_confirmations": self.strong_confirmations,
        }


class WorkflowManager:
    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self.settings = settings or {}

    def build_default_plan(self) -> WorkflowPlan:
        workflow = self.settings.get("workflow", {})
        defaults = workflow.get("defaults", {})
        steps = default_steps(defaults)
        selected = {step.name: bool(defaults.get(step.name, step.enabled_by_default)) for step in steps}
        return WorkflowPlan(
            steps=steps,
            selected_steps=selected,
            global_profile=workflow.get("default_profile", "quiet"),
            noise_level=int(workflow.get("default_noise_level", 3)),
            filters=workflow.get("filters", {"ignore_status": [404]}),
            rate_limit=workflow.get("rate_limit", {}).get("quiet", {"rate": 5, "threads": 3}),
            save_decisions=bool(workflow.get("save_decisions_per_project", True)),
        )

    def build_interactive_plan(self, interactive_session: InteractiveSession) -> WorkflowPlan:
        plan = self.build_default_plan()
        plan.global_profile = interactive_session.ask_scan_profile(plan.global_profile)
        plan.noise_level = interactive_session.ask_noise_level(plan.noise_level)
        plan.filters = interactive_session.ask_filters()
        plan.rate_limit = interactive_session.ask_rate_limit(default_rate=int(plan.rate_limit.get("rate", 5)))
        for index, step in enumerate(plan.steps, start=1):
            interactive_session.print_step_banner(f"[{index}/{len(plan.steps)}] {step.name}")
            if step.description:
                interactive_session.console.print(f"Description: {step.description}")
            if step.can_be_noisy:
                interactive_session.console.print("[yellow]This step can generate traffic.[/yellow]")
            if step.requires_tokens:
                interactive_session.console.print("[yellow]Requires two authorized accounts/tokens.[/yellow]")
            launch = interactive_session.ask_yes_no("Launch?", default=plan.selected_steps.get(step.name, False))
            if launch and step.requires_tokens:
                launch = interactive_session.ask_yes_no("Do you have token A and token B?", default=False)
                if launch:
                    plan.allow_post = interactive_session.ask_yes_no("Allow POST requests?", default=False)
                    plan.allow_state_changing = interactive_session.ask_state_changing_permission()
            if launch and step.can_change_state:
                plan.allow_state_changing = interactive_session.ask_state_changing_permission()
                launch = plan.allow_state_changing
            if launch and self._needs_strong_confirmation(step, plan):
                confirmed = interactive_session.ask_strong_confirmation()
                plan.strong_confirmations[step.name] = confirmed
                if not confirmed:
                    launch = False
                    plan.skipped_reasons[step.name] = "strong confirmation not provided"
            plan.selected_steps[step.name] = launch
        plan.save_decisions = interactive_session.ask_save_decisions()
        interactive_session.print_decision_summary(plan.selected_steps)
        return plan

    def run_plan(self, plan: WorkflowPlan, context: dict[str, Any]) -> dict[str, Any]:
        results = {"executed": [], "skipped": [], "dry_run": plan.dry_run}
        context["workflow_options"] = {
            "profile": plan.global_profile,
            "noise_level": plan.noise_level,
            "filters": plan.filters,
            "rate_limit": plan.rate_limit,
            "allow_state_changing": plan.allow_state_changing,
            "dry_run": plan.dry_run,
            "project_path": str(context["storage"].root),
        }
        if plan.dry_run:
            for step in plan.steps:
                if plan.selected_steps.get(step.name):
                    results["skipped"].append({"step": step.name, "reason": "dry_run"})
            self.save_plan(context["storage"].root, plan, context.get("project"))
            return results
        for step in plan.steps:
            if not plan.selected_steps.get(step.name, False):
                results["skipped"].append(self.skip_step(step, plan.skipped_reasons.get(step.name, "not selected")))
                continue
            if step.can_be_noisy and plan.noise_level == 1:
                results["skipped"].append(self.skip_step(step, "noise level 1 disables noisy steps"))
                continue
            outcome = self.run_step(step, context)
            results["executed"].append({"step": step.name, "result": outcome})
        if plan.save_decisions:
            self.save_plan(context["storage"].root, plan, context.get("project"))
        return results

    def skip_step(self, step: WorkflowStep, reason: str) -> dict[str, str]:
        return {"step": step.name, "reason": reason}

    def run_step(self, step: WorkflowStep, context: dict[str, Any]) -> dict[str, Any]:
        runners = {
            "scope_validation": lambda ctx: {"status": "ok", "target": ctx["target"]},
            "passive_recon": run_recon,
            "tech_detection": run_recon,
            "js_analysis": run_js,
            "content_discovery": lambda ctx: run_fuzz(ctx, wordlist="wordlists/small.txt", threads=min(3, int(ctx.get("threads", 1))), calibrate=True),
            "api_inventory": run_api,
            "cors_check": run_cors,
            "oauth_check": run_oauth,
            "graphql_check": run_graphql,
            "xss_reflection_checker": run_xss_reflection,
            "exploitdb_intelligence": run_exploitdb_intelligence,
            "report_generation": lambda ctx: generate_report(ctx, "markdown"),
        }
        runner = runners.get(step.name)
        if not runner:
            return {"status": "skipped", "reason": "runner not implemented"}
        if step.name == "idor_bola_helper":
            return {"status": "skipped", "reason": "requires token-a/token-b via dedicated idor command"}
        result = runner(context)
        if isinstance(result, list):
            return {"status": "ok", "findings": len(result)}
        return {"status": "ok", "result": result}

    def save_plan(self, project_path: str | Path, plan: WorkflowPlan, project: str | None = None) -> Path:
        path = Path(project_path) / "workflow_plan.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(plan.to_dict(project=project), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def load_plan(self, project_path: str | Path) -> WorkflowPlan:
        path = Path(project_path) / "workflow_plan.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        plan = self.build_default_plan()
        plan.selected_steps.update(data.get("steps", {}))
        plan.global_profile = data.get("profile", plan.global_profile)
        plan.noise_level = int(data.get("noise_level", plan.noise_level))
        plan.filters = data.get("filters", plan.filters)
        plan.rate_limit = data.get("rate_limit", plan.rate_limit)
        plan.allow_state_changing = bool(data.get("safety", {}).get("allow_state_changing", False))
        plan.dry_run = bool(data.get("dry_run", False))
        return plan

    def _needs_strong_confirmation(self, step: WorkflowStep, plan: WorkflowPlan) -> bool:
        return step.can_change_state or (step.requires_tokens and plan.allow_state_changing) or (step.can_be_noisy and plan.global_profile == "deep") or requires_strong_confirmation_for_noise(plan.noise_level)


def default_steps(defaults: dict[str, Any] | None = None) -> list[WorkflowStep]:
    defaults = defaults or {}
    specs = [
        ("scope_validation", "validate target against allowed scope", "core.scope", True, False, False, False, False, "quiet", "low"),
        ("passive_recon", "passive DNS/subdomain/source analysis", "modules.recon", True, False, False, False, False, "quiet", "low"),
        ("tech_detection", "detect technologies from headers, HTML and JS", "modules.tech_detector", True, False, False, False, False, "quiet", "low"),
        ("js_analysis", "download and analyze JS files for endpoints and secrets", "modules.js_analyzer", True, False, False, False, False, "quiet", "low"),
        ("content_discovery", "light directory/file discovery using SecLists", "modules.content_discovery", False, False, False, True, False, "quiet", "medium"),
        ("api_inventory", "safe API endpoint inventory", "modules.api_analyzer", True, False, False, False, False, "quiet", "low"),
        ("cors_check", "safe CORS header checks", "modules.cors_checker", False, False, False, False, False, "quiet", "low"),
        ("oauth_check", "safe OAuth redirect parameter checks", "modules.oauth_checker", False, False, False, False, False, "quiet", "medium"),
        ("graphql_check", "safe GraphQL detection and introspection check", "modules.graphql_analyzer", False, False, False, False, False, "quiet", "medium"),
        ("idor_bola_helper", "compare API responses between authorized users", "modules.idor_helper", False, True, True, False, False, "quiet", "medium"),
        ("xss_reflection_checker", "safe reflection checker without browser execution", "modules.xss_reflection_checker", False, False, False, False, False, "quiet", "low"),
        ("exploitdb_intelligence", "local metadata-only Exploit-DB scoring", "modules.exploitdb_intelligence", True, False, False, False, False, "quiet", "low"),
        ("report_generation", "generate Markdown report", "modules.report_generator", True, False, False, False, False, "quiet", "low"),
    ]
    return [
        WorkflowStep(
            name=name,
            description=description,
            module_name=module,
            enabled_by_default=bool(defaults.get(name, enabled)),
            requires_auth=requires_auth,
            requires_tokens=requires_tokens,
            can_be_noisy=can_be_noisy,
            can_change_state=can_change_state,
            recommended_profile=profile,
            risk_level=risk,
        )
        for name, description, module, enabled, requires_auth, requires_tokens, can_be_noisy, can_change_state, profile, risk in specs
    ]
