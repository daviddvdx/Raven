from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
import yaml

from core.banner import print_banner, print_error, print_run_config, print_section, print_success, print_warning
from core.exploitdb_manager import ExploitDBManager
from core.http_client import HTTPClient
from core.interactive import InteractiveSession
from core.logger import Logger
from core.noise_guard import NoiseGuard, get_noise_profile, is_noise_allowed_for_yes, noise_level_config, requires_strong_confirmation_for_noise
from core.rate_limiter import RateLimiter
from core.scope import Scope, ScopeError
from core.storage import Storage
from core.utils import parse_int_csv, project_from_target, slugify
from core.workflow import WorkflowManager
from core.wordlist_manager import WordlistManager
from modules.api_analyzer import run_api
from modules.content_discovery import DEFAULT_EXTENSIONS, DEFAULT_FILTER_STATUS, DEFAULT_MATCHERS, default_wordlist, run_fuzz
from modules.cors_checker import run_cors
from modules.crawler import run_crawler
from modules.graphql_analyzer import run_graphql
from modules.idor_helper import load_endpoints, run_idor
from modules.js_analyzer import run_js
from modules.path_normalizer import run_normalize
from modules.recon import run_recon
from modules.report_generator import generate_report
from modules.xss_reflection_checker import run_xss_reflection

app = typer.Typer(
    name="raven",
    help="RAVEN - Reconnaissance & API Vulnerability Enumeration Navigator",
    no_args_is_help=True,
)

VALID_PROFILES = {"quiet", "balanced", "deep"}


def load_settings(path: str = "config/settings.yaml") -> dict:
    settings_path = Path(path)
    if not settings_path.exists():
        settings_path = Path("config/settings.example.yaml")
    if not settings_path.exists():
        return {}
    return yaml.safe_load(settings_path.read_text(encoding="utf-8")) or {}


def target_from_scope(scope_obj: Scope) -> str:
    if scope_obj.allowed_urls:
        return scope_obj.allowed_urls[0]
    for domain in scope_obj.allowed_domains:
        if domain.startswith("*."):
            continue
        return f"https://{domain}"
    raise ScopeError("Impossible de deduire une cible depuis le scope. Fournis --target.")


def build_context(
    mode: str,
    scope_path: str,
    target: str,
    project: Optional[str] = None,
    timeout: float = 10.0,
    threads: int = 5,
    follow_redirects: bool = False,
    output_file: Optional[str] = None,
    extra_config: Optional[dict] = None,
    profile: str = "quiet",
    confirm_deep: bool = False,
    verify_tls: bool = True,
):
    if profile not in VALID_PROFILES:
        print_error(f"Profil invalide: {profile}. Utilise quiet, balanced ou deep.")
        raise typer.Exit(1)
    if profile == "deep" and not confirm_deep:
        print_error("Le profil deep exige une confirmation explicite avec --confirm-deep.")
        raise typer.Exit(1)
    profile_config = get_noise_profile(profile)
    if timeout == 10.0:
        timeout = float(profile_config["timeout"])
    if threads == 5:
        threads = int(profile_config["threads"])
    try:
        scope = Scope.from_file(scope_path)
        scope.validate_url(target)
    except ScopeError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    project_name = slugify(project) if project else project_from_target(target)
    storage = Storage(project_name)
    logger = Logger()
    noise_guard = NoiseGuard(profile, logger=logger)
    rate_limiter = RateLimiter(min(scope.requests_per_second(), float(profile_config["requests_per_second"])))
    proxy = scope.proxy.get("url") if scope.proxy.get("enabled") else None
    http_client = HTTPClient(
        timeout=timeout,
        headers=scope.headers,
        follow_redirects=follow_redirects,
        proxy=proxy,
        retries=1,
        rate_limiter=rate_limiter,
        storage=storage,
        noise_guard=noise_guard,
        verify_tls=verify_tls,
    )
    config = {
        "Target": target,
        "Scope": scope_path,
        "Output file": output_file or f"results/{project_name}",
        "File format": (extra_config or {}).get("File format", "json"),
        "Follow redirects": str(follow_redirects).lower(),
        "Calibration": (extra_config or {}).get("Calibration"),
        "Timeout": timeout,
        "Threads": threads,
        "Rate limit": f"{rate_limiter.requests_per_second} req/s",
        "Profile": profile,
        "Proxy": proxy or "disabled",
        "TLS verify": str(verify_tls).lower(),
    }
    if extra_config:
        config.update(extra_config)
    storage.write_json("run_config.json", config)
    print_banner(mode)
    print_run_config(config)
    return {
        "project": project_name,
        "target": target,
        "scope": scope,
        "config": config,
        "http_client": http_client,
        "storage": storage,
        "logger": logger,
        "rate_limiter": rate_limiter,
        "noise_guard": noise_guard,
        "profile": profile,
        "threads": threads,
    }


@app.command()
def init(project: str = typer.Option(..., "--project", help="Project name to initialize.")) -> None:
    print_banner("init")
    project_name = slugify(project)
    storage = Storage(project_name)
    print_run_config({"Project": project_name, "Output file": f"results/{project_name}", "Proxy": "disabled"})
    scope_target = Path("config") / f"{project_name}.scope.yaml"
    if not scope_target.exists():
        scope_target.write_text(Path("config/scope.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        print_success(f"Scope example created: {scope_target}")
    print_success(f"Project initialized: {storage.root}")


@app.command()
def scan(
    scope: str = typer.Option(..., "--scope", help="Scope YAML file."),
    target: str = typer.Option(..., "--target", help="Target URL."),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    follow_redirects: bool = typer.Option(False, "--follow-redirects"),
    insecure: bool = typer.Option(False, "--insecure", help="Disable TLS certificate verification for authorized labs/CTFs."),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("scan", scope, target, project, timeout, threads, follow_redirects, "results/<project>/recon_results.json", profile=profile, confirm_deep=confirm_deep, verify_tls=not insecure)
    findings = run_recon(context)
    print_success(f"{len(findings)} finding(s) ecrit(s) dans results/{context['project']}")
    context["http_client"].close()


@app.command()
def crawl(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target"),
    depth: int = typer.Option(2, "--depth"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("crawl", scope, target, project, timeout, threads, False, "results/<project>/crawler_results.json", {"Depth": depth}, profile=profile, confirm_deep=confirm_deep)
    findings = run_crawler(context, depth=depth)
    print_success(f"Crawl termine avec {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def js(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("js", scope, target, project, timeout, threads, False, "results/<project>/js_findings.md", profile=profile, confirm_deep=confirm_deep)
    findings = run_js(context)
    print_success(f"Analyse JS terminee avec {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def fuzz(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target", help="Use FUZZ as insertion point."),
    wordlist: Optional[str] = typer.Option(None, "--wordlist"),
    extensions: str = typer.Option(",".join(DEFAULT_EXTENSIONS), "--extensions"),
    filter_status: str = typer.Option("403,404", "--filter-status"),
    filter_size: Optional[int] = typer.Option(None, "--filter-size"),
    filter_words: Optional[int] = typer.Option(None, "--filter-words"),
    filter_lines: Optional[int] = typer.Option(None, "--filter-lines"),
    filter_regex: Optional[str] = typer.Option(None, "--filter-regex"),
    match_status: str = typer.Option("200,204,301,302,307,308,401", "--match-status", "--matcher"),
    match_regex: Optional[str] = typer.Option(None, "--match-regex"),
    calibrate: bool = typer.Option(True, "--calibrate/--no-calibration"),
    ignore_baseline: bool = typer.Option(False, "--ignore-baseline"),
    exploitdb_prioritize: bool = typer.Option(True, "--exploitdb-prioritize/--no-exploitdb-prioritize"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit"),
    follow_redirects: bool = typer.Option(False, "--follow-redirects"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    manager = WordlistManager()
    selected_wordlists = [wordlist] if wordlist else [str(item) for item in manager.select_wordlists(profile, "web_content", allow_deep=confirm_deep)]
    selected_wordlist = ", ".join(selected_wordlists) if selected_wordlists else default_wordlist()
    context = build_context(
        "fuzz",
        scope,
        target,
        project,
        timeout,
        threads,
        follow_redirects,
        "results/<project>/fuzz_results.json",
        {
            "Method": "GET",
            "URL": target,
            "Wordlist": selected_wordlist,
            "Extensions": extensions,
            "Calibration": str(calibrate).lower(),
            "Wordlist profile": profile,
            "Matcher": match_status,
            "Filter status": filter_status,
            "Filter size": filter_size,
            "Exploit-DB prioritize": exploitdb_prioritize,
        },
        profile=profile,
        confirm_deep=confirm_deep,
    )
    if rate_limit:
        context["rate_limiter"].requests_per_second = rate_limit
    findings = run_fuzz(
        context,
        wordlist=selected_wordlists,
        extensions=extensions,
        matcher_status=parse_int_csv(match_status) or DEFAULT_MATCHERS,
        filter_status=parse_int_csv(filter_status) or DEFAULT_FILTER_STATUS,
        filter_size=filter_size,
        filter_words=filter_words,
        filter_lines=filter_lines,
        filter_regex=filter_regex,
        match_regex=match_regex,
        calibrate=calibrate,
        ignore_baseline=ignore_baseline,
        exploitdb_prioritize=exploitdb_prioritize and profile in {"quiet", "balanced"},
        threads=context["threads"],
    )
    print_success(f"Fuzz termine: {len(findings)} resultat(s) retenu(s).")
    context["http_client"].close()


@app.command()
def api(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("api", scope, target, project, timeout, threads, False, "results/<project>/api_results.json", profile=profile, confirm_deep=confirm_deep)
    findings = run_api(context)
    print_success(f"API checks termines: {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def normalize(
    scope: str = typer.Option(..., "--scope"),
    base: str = typer.Option(..., "--base"),
    path: str = typer.Option(..., "--path"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("normalize", scope, base, project, timeout, threads, False, "results/<project>/normalize_results.json", {"Base": base, "Path": path}, profile=profile, confirm_deep=confirm_deep)
    findings = run_normalize(context, base, path)
    print_success(f"Normalisation terminee: {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def cors(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("cors", scope, target, project, timeout, threads, False, "results/<project>/cors_results.json", profile=profile, confirm_deep=confirm_deep)
    findings = run_cors(context)
    print_success(f"CORS checks termines: {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def graphql(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context("graphql", scope, target, project, timeout, threads, False, "results/<project>/graphql_results.json", profile=profile, confirm_deep=confirm_deep)
    findings = run_graphql(context)
    print_success(f"GraphQL checks termines: {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def wordlists(profile: str = typer.Option("quiet", "--profile")) -> None:
    manager = WordlistManager()
    status = manager.status(profile=profile)
    print_banner("wordlists")
    print_run_config(
        {
            "SecLists detected": status.seclists_detected,
            "SecLists path": status.base_path or "not found",
            "Profile": profile,
            "Install Kali": "sudo apt install seclists",
        }
    )
    print_section("Existing wordlists")
    any_existing = False
    for profile_name, modes in status.profiles.items():
        for mode_name in modes:
            existing, _missing = manager.check_wordlists(profile_name, mode_name)
            for item in existing:
                any_existing = True
                print_success(f"{profile_name}/{mode_name}: {item}")
    if not any_existing:
        for item in status.fallback:
            print_success(f"fallback: {item}")
    print_section("Missing wordlists")
    for profile_name, modes in status.profiles.items():
        for mode_name in modes:
            _existing, missing = manager.check_wordlists(profile_name, mode_name)
            for item in missing:
                print_warning(f"{profile_name}/{mode_name}: {item}")
    print_section("Profiles")
    for name in status.profiles:
        print_success(name)


@app.command()
def exploitdb(
    status: bool = typer.Option(False, "--status"),
    search_tech: Optional[str] = typer.Option(None, "--search-tech"),
    search_cve: Optional[str] = typer.Option(None, "--search-cve"),
    vuln_class: Optional[str] = typer.Option(None, "--class"),
    profile: str = typer.Option("quiet", "--profile"),
    refresh_cache: bool = typer.Option(False, "--refresh-cache"),
    metadata_only: bool = typer.Option(True, "--metadata-only/--allow-non-metadata-mode"),
    allow_poc_text_analysis: bool = typer.Option(False, "--allow-poc-text-analysis"),
    limit: int = typer.Option(10, "--limit"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    manager = ExploitDBManager(
        profile=profile,
        refresh_cache=refresh_cache,
        metadata_only=metadata_only,
        allow_poc_text_analysis=allow_poc_text_analysis,
    )
    if json_output:
        payload = build_exploitdb_cli_payload(manager, status, search_tech, search_cve, vuln_class, limit, metadata_only, allow_poc_text_analysis)
        import json as json_module

        typer.echo(json_module.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_banner("exploitdb")
    manager_status = manager.get_status()
    print_run_config(
        {
            "Exploit-DB detected": manager_status.detected,
            "Base path": manager_status.base_path or "not found",
            "SearchSploit": "available" if manager_status.searchsploit_found else "not found",
            "Entries indexed": manager_status.entries_count,
            "Cache": manager_status.cache_file,
            "Mode": "metadata_only" if metadata_only else "metadata-plus-safe-patterns",
            "Payload extraction": "disabled",
            "Install": "sudo apt install exploitdb",
            "Update": "searchsploit -u",
            "Profile": profile,
        }
    )
    if status and not any([search_tech, search_cve, vuln_class]):
        for warning in manager_status.warnings:
            print_warning(warning)
        return
    rows = select_exploitdb_rows(manager, search_tech, search_cve, vuln_class, limit)
    print_section("Exploit-DB metadata matches")
    for entry in rows:
        cves = ", ".join(entry.cve_ids) if entry.cve_ids else "n/a"
        print_success(f"EDB-{entry.edb_id} | {entry.date} | {entry.exploit_type}/{entry.platform} | {entry.vulnerability_class} | CVE: {cves}")
        typer.echo(f"  {entry.title}")
        typer.echo(f"  {entry.safe_summary}")


def select_exploitdb_rows(manager: ExploitDBManager, search_tech: str | None, search_cve: str | None, vuln_class: str | None, limit: int):
    if search_tech:
        return manager.search_by_technology(search_tech, limit=limit)
    if search_cve:
        return manager.search_by_cve(search_cve, limit=limit)
    if vuln_class:
        return manager.search_by_vulnerability_class(vuln_class, limit=limit)
    return manager.entries[:limit]


def build_exploitdb_cli_payload(
    manager: ExploitDBManager,
    status_requested: bool,
    search_tech: str | None,
    search_cve: str | None,
    vuln_class: str | None,
    limit: int,
    metadata_only: bool,
    allow_poc_text_analysis: bool,
) -> dict:
    status_data = manager.get_status().to_dict()
    status_data["metadata_only"] = metadata_only
    status_data["payload_extraction"] = "disabled"
    status_data["allow_poc_text_analysis"] = allow_poc_text_analysis
    rows = [] if status_requested and not any([search_tech, search_cve, vuln_class]) else select_exploitdb_rows(manager, search_tech, search_cve, vuln_class, limit)
    return {
        "status": status_data,
        "results": [
            {
                "edb_id": entry.edb_id,
                "title": entry.title,
                "date": entry.date,
                "type": entry.exploit_type,
                "platform": entry.platform,
                "cve_ids": entry.cve_ids,
                "vulnerability_class": entry.vulnerability_class,
                "safe_summary": entry.safe_summary,
            }
            for entry in rows
        ],
    }


@app.command()
def workflow(
    scope: str = typer.Option(..., "--scope"),
    target: Optional[str] = typer.Option(None, "--target"),
    interactive: Optional[bool] = typer.Option(None, "--interactive/--no-interactive"),
    profile: str = typer.Option("quiet", "--profile"),
    noise: int = typer.Option(3, "--noise", min=1, max=10),
    yes: bool = typer.Option(False, "--yes"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    resume_plan: bool = typer.Option(False, "--resume-plan"),
    save_plan: bool = typer.Option(False, "--save-plan"),
    skip: list[str] = typer.Option([], "--skip"),
    only: list[str] = typer.Option([], "--only"),
    project: Optional[str] = typer.Option(None, "--project"),
) -> None:
    settings = load_settings()
    try:
        scope_obj = Scope.from_file(scope)
        selected_target = target or target_from_scope(scope_obj)
        scope_obj.validate_url(selected_target)
    except ScopeError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    if yes and not is_noise_allowed_for_yes(noise):
        print_error("--yes ne peut pas etre utilise avec un niveau de bruit 9-10.")
        raise typer.Exit(1)
    if profile == "deep" and yes:
        print_error("--yes ne peut pas accepter le profil deep.")
        raise typer.Exit(1)

    workflow_settings = settings.get("workflow", {})
    use_interactive = bool(workflow_settings.get("interactive", True)) if interactive is None else interactive
    manager = WorkflowManager(settings)
    project_name = slugify(project) if project else project_from_target(selected_target)
    plan_storage = Storage(project_name)
    if resume_plan and plan_storage.path("workflow_plan.json").exists():
        plan = manager.load_plan(plan_storage.root)
    elif use_interactive and not yes:
        session = InteractiveSession(settings=settings)
        print_banner("workflow")
        print_run_config(
            {
                "Target": selected_target,
                "Profile default": profile,
                "Noise default": f"{noise}/10",
                "Interactive": True,
                "Scope": scope,
            }
        )
        plan = manager.build_interactive_plan(session)
    else:
        plan = manager.build_default_plan()

    plan.global_profile = profile or plan.global_profile
    plan.noise_level = noise or plan.noise_level
    plan.dry_run = dry_run
    if save_plan:
        plan.save_decisions = True
    if yes:
        for step in plan.steps:
            if step.requires_tokens or step.can_change_state or (step.can_be_noisy and not step.enabled_by_default):
                plan.selected_steps[step.name] = False
                plan.skipped_reasons[step.name] = "--yes does not enable dangerous or noisy disabled-by-default steps"
    if only:
        allowed = set(only)
        for step in plan.steps:
            plan.selected_steps[step.name] = step.name in allowed
    for step_name in skip:
        plan.selected_steps[step_name] = False
        plan.skipped_reasons[step_name] = "skipped by CLI"
    if requires_strong_confirmation_for_noise(plan.noise_level) and not use_interactive and not dry_run:
        print_error("Noise 7-10 exige une confirmation interactive forte. Relance avec --interactive.")
        raise typer.Exit(1)

    noise_cfg = noise_level_config(plan.noise_level)
    context = build_context(
        "workflow",
        scope,
        selected_target,
        project=project_name,
        timeout=float(noise_cfg.get("timeout", get_noise_profile(plan.global_profile)["timeout"])),
        threads=int(noise_cfg.get("threads", get_noise_profile(plan.global_profile)["threads"])),
        follow_redirects=False,
        output_file=f"results/{project_name}/workflow_plan.json",
        extra_config={
            "Interactive": use_interactive,
            "Noise": plan.noise_level,
            "Only": ", ".join(only) if only else "none",
            "Skip": ", ".join(skip) if skip else "none",
            "Dry-run": dry_run,
        },
        profile=plan.global_profile,
        confirm_deep=True,
    )
    context["workflow_plan"] = plan.to_dict(project=project_name)
    result = manager.run_plan(plan, context)
    context["storage"].write_json("workflow_result.json", result)
    print_section("Workflow result")
    print_success(f"Executed: {len(result['executed'])}, skipped: {len(result['skipped'])}, dry-run: {dry_run}")
    context["http_client"].close()


@app.command()
def xss(
    scope: str = typer.Option(..., "--scope"),
    target: str = typer.Option(..., "--target"),
    payload_file: Optional[str] = typer.Option(None, "--payload-file"),
    max_payloads: int = typer.Option(5, "--max-payloads"),
    safe_only: bool = typer.Option(True, "--safe-only/--allow-custom-payloads"),
    no_browser_execution: bool = typer.Option(True, "--no-browser-execution/--browser-execution"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    context = build_context(
        "xss",
        scope,
        target,
        project,
        timeout,
        threads,
        False,
        "results/<project>/xss_reflections.json",
        {"Safe only": safe_only, "Max payloads": max_payloads, "Browser execution": str(not no_browser_execution).lower()},
        profile=profile,
        confirm_deep=confirm_deep,
    )
    findings = run_xss_reflection(context, payload_file=payload_file, max_payloads=max_payloads, safe_only=safe_only, no_browser_execution=no_browser_execution)
    print_success(f"XSS reflection checks termines: {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def idor(
    scope: str = typer.Option(..., "--scope"),
    endpoints: str = typer.Option(..., "--endpoints"),
    token_a: str = typer.Option(..., "--token-a"),
    token_b: str = typer.Option(..., "--token-b"),
    token_admin: Optional[str] = typer.Option(None, "--token-admin"),
    allow_state_changing: bool = typer.Option(False, "--allow-state-changing"),
    max_endpoints: int = typer.Option(200, "--max-endpoints"),
    timeout: float = typer.Option(10.0, "--timeout"),
    threads: int = typer.Option(5, "--threads"),
    project: Optional[str] = typer.Option(None, "--project"),
    profile: str = typer.Option("quiet", "--profile"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
) -> None:
    loaded = load_endpoints(endpoints, max_endpoints=1)
    if not loaded:
        print_error(f"Aucun endpoint lisible dans {endpoints}")
        raise typer.Exit(1)
    context = build_context(
        "idor",
        scope,
        loaded[0],
        project,
        timeout,
        threads,
        False,
        "results/<project>/idor_matrix.json",
        {"Endpoints": endpoints, "Read only": str(not allow_state_changing).lower()},
        profile=profile,
        confirm_deep=confirm_deep,
    )
    findings = run_idor(context, endpoints, token_a, token_b, token_admin=token_admin, allow_state_changing=allow_state_changing, max_endpoints=max_endpoints)
    print_success(f"IDOR/BOLA checks termines: {len(findings)} finding(s).")
    context["http_client"].close()


@app.command()
def report(
    project: str = typer.Option(..., "--project"),
    format: str = typer.Option("markdown", "--format", help="markdown, json or csv."),
) -> None:
    print_banner("report")
    project_name = slugify(project)
    storage = Storage(project_name)
    context = {"project": project_name, "storage": storage, "scope": None}
    print_run_config({"Project": project_name, "Output file": f"results/{project_name}/reports/report.{format}", "File format": format, "Proxy": "disabled"})
    if format not in {"markdown", "json", "csv"}:
        print_warning("Format inconnu, utilisation de markdown.")
        format = "markdown"
    path = generate_report(context, format)
    print_section("Report")
    print_success(f"Report generated: {path}")


if __name__ == "__main__":
    app()
