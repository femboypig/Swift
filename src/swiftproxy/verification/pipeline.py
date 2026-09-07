from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

from swiftproxy.storage import read_jsonl, write_json, write_jsonl
from swiftproxy.subscriptions.staging import stage_output
from swiftproxy.verification.candidate import CandidateVerifier
from swiftproxy.verification.constants import HELD_EXIT_CODE, MIN_THROUGHPUT_KBPS
from swiftproxy.verification.health import _wait_for_healthy_path
from swiftproxy.verification.results import _hold_population_collapse
from swiftproxy.verification.scheduler import run_candidates


async def run_generation(root: Path, core: str) -> int:
    generation_dir = root / "data/ru-generation"
    manifest = json.loads((generation_dir / "manifest.json").read_text())
    candidates = read_jsonl(generation_dir / "candidates.jsonl")
    evidence = json.loads((generation_dir / "white-evidence.json").read_text())
    if len(candidates) != manifest["ru_expected"] or len(
        {item["fingerprint"] for item in candidates}
    ) != len(candidates):
        raise RuntimeError("invalid collected generation")
    settings = tomllib.loads((root / "config.toml").read_text())
    try:
        previous_stats = json.loads((root / "stats.json").read_text())
    except FileNotFoundError:
        previous_stats = {}
    ru = settings["ru"]
    positive = (
        "resolution_concurrency",
        "endpoint_concurrency",
        "https_concurrency",
        "stability_concurrency",
        "download_concurrency",
        "diagnostic_concurrency",
    )
    if any((int(ru[key]) < 1 for key in positive)):
        raise ValueError("RU stage concurrency must be positive")
    if float(ru["preflight_timeout"]) <= 0:
        raise ValueError("RU preflight timeout must be positive")
    recovery_attempts = int(ru["path_recovery_attempts"])
    recovery_delay = float(ru["path_recovery_delay_seconds"])
    recovery_confirmations = int(ru["path_recovery_confirmations"])
    path_check_interval = int(ru["path_check_interval"])
    if recovery_attempts < 1 or recovery_delay < 0 or recovery_confirmations < 1:
        raise ValueError("RU path recovery settings are invalid")
    if recovery_confirmations > recovery_attempts:
        raise ValueError("RU path confirmations cannot exceed recovery attempts")
    if path_check_interval < 1:
        raise ValueError("RU path check interval must be positive")
    per_transfer_bps = int(ru["download_bandwidth_bps"]) // int(ru["download_concurrency"])
    if per_transfer_bps <= MIN_THROUGHPUT_KBPS * 1024:
        raise ValueError("RU download budget must stay above the quality threshold")
    interface = os.environ.get("SWIFT_BIND_INTERFACE", "")
    if not interface:
        raise RuntimeError("SWIFT_BIND_INTERFACE is required")
    preflight_health, preflight_checks = await _wait_for_healthy_path(
        interface,
        core,
        float(ru["preflight_timeout"]),
        recovery_attempts,
        recovery_delay,
        recovery_confirmations,
        "preflight",
    )
    publication = root / "data/ru-publication"
    if not preflight_health.healthy:
        write_json(
            publication / "result-manifest.json",
            {
                **manifest,
                "complete": False,
                "state": "HELD",
                "reason": "RU_PREFLIGHT_FAILED",
                "path_mode": preflight_health.control.get("path_mode"),
                "core_control": preflight_health.core_control,
                "path_checks": {"preflight": preflight_checks},
            },
        )
        return HELD_EXIT_CODE
    control = preflight_health.control
    history_path = root / "data/ru-history.json"
    history = (
        json.loads(history_path.read_text())
        if history_path.exists()
        else {"schema_version": 1, "vantage": "ru", "configs": {}}
    )
    if history.get("vantage") != "ru":
        history = {"schema_version": 1, "vantage": "ru", "configs": {}}
    verifier = CandidateVerifier(core, manifest, settings, history, evidence, control, interface)
    outcome = await run_candidates(candidates, verifier)
    results = outcome.results
    complete = outcome.complete
    run_failure = outcome.failure
    running_path_checks = outcome.running_checks
    freshness_path_checks = outcome.freshness_checks
    freshness_candidates = outcome.freshness_candidates
    deferred = [
        result
        for result in results
        if result.get("final", {}).get("reason") == "DEFER_LOCAL_CONGESTION"
    ]
    result_fps = [result["fingerprint"] for result in results]
    expected_fps = {item["fingerprint"] for item in candidates}
    complete = (
        complete
        # A single result may still be deferred after its retry because the local
        # verifier briefly became congested. It is a terminal non-PASS result,
        # so it cannot reach publication, but must not discard an otherwise
        # complete generation. More than one deferral signals local instability.
        and len(deferred) <= 1
        and (len(result_fps) == len(expected_fps))
        and (len(set(result_fps)) == len(result_fps))
        and (set(result_fps) == expected_fps)
    )
    performance = {
        "resolution": verifier.resolution_stage.summary(),
        "endpoint": verifier.endpoint_stage.summary(),
        "initial_https": verifier.initial_stage.summary(),
        "stability": verifier.stability_stage.summary(),
        "downloads": {"peak_active": verifier.governor.peak, "bytes": verifier.governor.bytes},
        "diagnostics": verifier.diagnostic_stage.summary(),
    }
    terminal_counts: dict[str, int] = {}
    for result in results:
        reason = str(result.get("final", {}).get("reason", "INCOMPLETE"))
        terminal_counts[reason] = terminal_counts.get(reason, 0) + 1
    freshness_passed = sum(
        (bool(result.get("freshness", {}).get("passed")) for result in freshness_candidates)
    )
    write_jsonl(
        publication / "ru-results.jsonl", sorted(results, key=lambda item: item["fingerprint"])
    )
    if not complete:
        write_json(
            publication / "result-manifest.json",
            {
                **manifest,
                "complete": False,
                "state": "RU_INCOMPLETE",
                "accounted_terminal": len(results),
                "untested": len(expected_fps - set(result_fps)),
                "verifier_download_bytes": verifier.governor.bytes,
                "path_mode": control["path_mode"],
                "performance": performance,
                "run_failure": run_failure,
                "path_checks": {
                    "preflight": preflight_checks,
                    "running": running_path_checks,
                    "freshness": freshness_path_checks,
                },
                "terminal_counts": dict(sorted(terminal_counts.items())),
                "freshness": {
                    "expected": len(freshness_candidates),
                    "passed": freshness_passed,
                    "failed": len(freshness_candidates) - freshness_passed,
                },
            },
        )
        return HELD_EXIT_CODE if run_failure == "RU_PATH_UNHEALTHY" else 1
    stats = stage_output(
        publication,
        manifest,
        candidates,
        results,
        history,
        settings,
        terminal_counts,
        freshness_candidates,
        freshness_passed,
    )
    postflight_health, postflight_checks = await _wait_for_healthy_path(
        interface,
        core,
        float(ru["preflight_timeout"]),
        recovery_attempts,
        recovery_delay,
        recovery_confirmations,
        "postflight",
    )
    postflight = postflight_health.preflight
    postflight_core = postflight_health.core_control
    infrastructure_reasons = {"SPAWN_ERROR", "RESOURCE_ERROR", "LISTEN_TIMEOUT"}
    infrastructure_failures = sum(
        (terminal_counts.get(reason, 0) for reason in infrastructure_reasons)
    )
    infrastructure_collapse = len(results) >= 10 and infrastructure_failures / len(results) >= 0.6
    population_collapse = _hold_population_collapse(
        int(previous_stats.get("production", {}).get("all", 0)),
        stats["alive"],
        [*freshness_path_checks, *postflight_checks],
    )
    complete = (
        postflight_health.healthy and (not infrastructure_collapse) and (not population_collapse)
    )
    write_json(
        publication / "result-manifest.json",
        {
            **manifest,
            "complete": complete,
            "state": "RU_COMPLETE" if complete else "HELD",
            "hold_reason": "RU_CORE_INFRASTRUCTURE_COLLAPSE"
            if infrastructure_collapse
            else "RU_PATH_CORRELATED_POPULATION_COLLAPSE"
            if population_collapse
            else None
            if postflight_health.healthy
            else "RU_POSTFLIGHT_TIMEOUT"
            if postflight is None
            else "RU_POSTFLIGHT_FAILED",
            "accounted_terminal": len(results),
            "untested": 0,
            "ru_pass": stats["alive"],
            "main_output": stats["main"],
            "white_output": stats["white"],
            "all_output": stats["alive"],
            "verifier_download_bytes": verifier.governor.bytes,
            "path_mode": control["path_mode"],
            "preflight_ok": True,
            "postflight_ok": postflight_health.healthy,
            "postflight_core": postflight_core,
            "path_checks": {
                "preflight": preflight_checks,
                "running": running_path_checks,
                "freshness": freshness_path_checks,
                "postflight": postflight_checks,
            },
            "performance": performance,
            "terminal_counts": dict(sorted(terminal_counts.items())),
            "freshness": {
                "expected": len(freshness_candidates),
                "passed": freshness_passed,
                "failed": len(freshness_candidates) - freshness_passed,
            },
        },
    )
    return 0 if complete else HELD_EXIT_CODE
