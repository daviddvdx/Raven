"""Controlled content discovery with filters."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re
import uuid

from core.models import Finding, HTTPResult
from core.knowledge_loader import KnowledgeLoader
from core.scoring import score_endpoint
from core.utils import normalize_extension, parse_csv, read_wordlist
from core.wordlist_manager import WordlistManager

DEFAULT_EXTENSIONS = [".js", ".css", ".map", ".json", ".txt", ".html", ".svg", ".png", ".woff"]
DEFAULT_MATCHERS = {200, 204, 301, 302, 307, 308, 401}
DEFAULT_FILTER_STATUS = {403, 404}


def default_wordlist() -> str:
    kali = Path("/usr/share/wordlists/dirb/common.txt")
    if kali.exists():
        return str(kali)
    return "wordlists/small.txt"


def build_candidates(target: str, words: list[str], extensions: list[str]) -> list[str]:
    output: list[str] = []
    for word in words:
        variants = [word]
        variants.extend(f"{word}{ext}" for ext in extensions if not word.endswith(ext))
        for variant in variants:
            if "FUZZ" in target:
                output.append(target.replace("FUZZ", variant.lstrip("/")))
            else:
                output.append(f"{target.rstrip('/')}/{variant.lstrip('/')}")
    return output


def exploitdb_priority_words() -> list[str]:
    patterns = KnowledgeLoader().load_exploitdb_patterns()
    files = patterns.get("vulnerability_classes", {}).get("information_disclosure", {}).get("interesting_files", [])
    high_value_paths = [item.strip("/") for item in patterns.get("risk_modifiers", {}).get("high_value_paths", [])]
    safe_static = ["swagger.json", "openapi.json", "actuator", "debug", "config", "backup"]
    return list(dict.fromkeys([*files, *high_value_paths, *safe_static]))[:30]


def result_signature(result: HTTPResult) -> tuple[int, int, int, int, str]:
    return (result.status_code, result.size, result.words, result.lines, result.body_hash)


def calibrate_baseline(context, samples: int = 4) -> list[dict]:
    target = context["target"]
    http_client = context["http_client"]
    storage = context["storage"]
    baselines: list[dict] = []
    for _index in range(max(3, min(samples, 5))):
        token = f"raven-calibration-{uuid.uuid4().hex}"
        url = target.replace("FUZZ", token) if "FUZZ" in target else f"{target.rstrip('/')}/{token}"
        try:
            result = http_client.get(url)
        except Exception:
            continue
        baselines.append(
            {
                "url": result.url,
                "status_code": result.status_code,
                "size": result.size,
                "words": result.words,
                "lines": result.lines,
                "body_hash": result.body_hash,
                "signature": list(result_signature(result)),
            }
        )
    storage.write_json("baselines/fuzz_baseline.json", baselines)
    return baselines


def matches_baseline(result: HTTPResult, baselines: list[dict]) -> bool:
    signature = list(result_signature(result))
    for baseline in baselines:
        if signature == baseline.get("signature"):
            return True
        if result.status_code == baseline.get("status_code") and result.body_hash == baseline.get("body_hash"):
            return True
        if result.status_code == baseline.get("status_code") and result.size == baseline.get("size") and result.words == baseline.get("words"):
            return True
    return False


def is_filtered(
    result: HTTPResult,
    filter_status: set[int],
    filter_size: int | None,
    filter_words: int | None,
    filter_lines: int | None,
    filter_regex: str | None = None,
) -> bool:
    if result.status_code in filter_status:
        return True
    if filter_size is not None and result.size == filter_size:
        return True
    if filter_words is not None and result.words == filter_words:
        return True
    if filter_lines is not None and result.lines == filter_lines:
        return True
    if filter_regex and re.search(filter_regex, result.body_text or "", re.IGNORECASE):
        return True
    return False


def score_result(result: HTTPResult) -> int:
    return score_endpoint(result.url, result.status_code, result.size).score


def fuzz(
    context,
    wordlist: str | list[str] | None = None,
    extensions: list[str] | None = None,
    matcher_status: set[int] | None = None,
    filter_status: set[int] | None = None,
    filter_size: int | None = None,
    filter_words: int | None = None,
    filter_lines: int | None = None,
    filter_regex: str | None = None,
    match_regex: str | None = None,
    calibrate: bool = True,
    ignore_baseline: bool = False,
    exploitdb_prioritize: bool = False,
    threads: int = 5,
) -> list[Finding]:
    storage = context["storage"]
    http_client = context["http_client"]
    target = context["target"]
    wordlist_paths = [wordlist] if isinstance(wordlist, str) or wordlist is None else list(wordlist)
    if wordlist_paths == [None]:
        wordlist_paths = [default_wordlist()]
    words: list[str] = []
    for wordlist_path in wordlist_paths:
        words.extend(read_wordlist(wordlist_path or default_wordlist()))
    if exploitdb_prioritize:
        words = list(dict.fromkeys([*exploitdb_priority_words(), *words]))
    exts = extensions if extensions is not None else DEFAULT_EXTENSIONS
    matchers = matcher_status or DEFAULT_MATCHERS
    blocked = filter_status or DEFAULT_FILTER_STATUS
    candidates = build_candidates(target, words, exts)
    seen_hashes: set[str] = set()
    findings: list[Finding] = []
    baselines = calibrate_baseline(context) if calibrate else []
    filtered_noise: list[dict] = []
    storage.write_json("wordlists_used.json", [str(item) for item in wordlist_paths])

    def fetch(url: str) -> HTTPResult | None:
        try:
            return http_client.get(url)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {executor.submit(fetch, url): url for url in candidates}
        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue
            if context.get("noise_guard") and context["noise_guard"].should_pause():
                break
            if result.status_code in {429, 503}:
                http_client.rate_limiter.slow_down()
            if result.status_code not in matchers:
                continue
            if match_regex and not re.search(match_regex, result.body_text or "", re.IGNORECASE):
                continue
            baseline_match = False if ignore_baseline else matches_baseline(result, baselines)
            if baseline_match:
                if result.status_code in {401, 403}:
                    filtered_noise.append({"url": result.url, "reason": "401/403 matched baseline noise", "status_code": result.status_code})
                    continue
                filtered_noise.append({"url": result.url, "reason": "matched calibration baseline", "status_code": result.status_code})
                continue
            if is_filtered(result, blocked, filter_size, filter_words, filter_lines, filter_regex):
                continue
            if result.body_hash in seen_hashes:
                filtered_noise.append({"url": result.url, "reason": "duplicate body hash", "status_code": result.status_code})
                continue
            seen_hashes.add(result.body_hash)
            score_data = score_endpoint(result.url, result.status_code, result.size, baseline_match=baseline_match)
            if exploitdb_prioritize and any(token in result.url.lower() for token in ("swagger", "openapi", "actuator", "debug", ".env", "backup", "config")):
                score_data.score = min(score_data.score + 2, 10)
                score_data.category = "exploit_pattern"
                score_data.reason = f"{score_data.reason}, Exploit-DB historical sensitive path pattern"
            finding = Finding(
                title=f"Contenu decouvert ({result.status_code})",
                severity="informational" if score_data.score < 5 else "low",
                endpoint=result.url,
                description="Une ressource repond avec un statut interessant apres fuzzing controle.",
                proof=f"status={result.status_code} size={result.size} words={result.words} lines={result.lines} hash={result.body_hash[:12]}",
                curl_command=result.curl_command,
                score=score_data.score,
                category=score_data.category,
                confidence=score_data.confidence,
                reason=score_data.reason,
                evidence=score_data.evidence,
                next_step=score_data.next_step,
                tags=["fuzz"],
            )
            findings.append(finding)
            storage.append_line("urls.txt", result.url)

    findings.sort(key=lambda item: item.score, reverse=True)
    storage.write_json("fuzz_results.json", [finding.to_dict() for finding in findings])
    storage.write_json("filtered_noise.json", filtered_noise)
    storage.save_findings(findings)
    return findings


def run_fuzz(context, **kwargs) -> list[Finding]:
    if isinstance(kwargs.get("extensions"), str):
        kwargs["extensions"] = [normalize_extension(item) for item in parse_csv(kwargs["extensions"])]
    if kwargs.get("wordlist_profile") and not kwargs.get("wordlist"):
        manager = WordlistManager()
        mode = kwargs.pop("wordlist_mode", "web_content")
        profile = kwargs.pop("wordlist_profile")
        allow_deep = kwargs.pop("allow_deep", False)
        kwargs["wordlist"] = [str(item) for item in manager.select_wordlists(profile, mode, allow_deep=allow_deep)]
    return fuzz(context, **kwargs)
