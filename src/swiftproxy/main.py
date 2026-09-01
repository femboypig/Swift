from __future__ import annotations

import argparse
import asyncio
import copy
import json
import logging
import os
import shutil
import subprocess
import sys
import tomllib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import ProxyConfig, TestResult
from .output import (
    alive_for_all,
    build_stats,
    check_outputs,
    suspicious_run,
    write_json,
    write_mac_handoff,
)
from .parsing import deduplicate, parse_sources, parse_uri
from .scoring import (
    add_observation,
    empty_history,
    failure_reasons,
    prune_history,
    rank_configs,
)
from .ru_probe import probe_ru_targets
from .sources import fetch_sources, source_specs
from .testing import preflight_targets, resolve_candidates, test_candidates
from .telemetry import cloud_result_record, population_record, write_jsonl
from .whitelist import (
    _visible_server_name,
    build_evidence,
    evidence_for,
    evidence_priority,
    evidence_specs,
)


LOGGER = logging.getLogger("swift")


class RunHeld(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid local data file: {path}") from exc


def load_settings(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def previous_subscription_configs(
    root: Path,
    history: dict[str, Any],
    allowed_sources: dict[str, set[str]] | None = None,
) -> list[ProxyConfig]:
    configs: list[ProxyConfig] = []
    rejected = 0
    records = history.get("configs", {})
    for lane in ("main", "white"):
        path = root / f"sub/{lane}.txt"
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                config = parse_uri(line)
            except ValueError:
                rejected += 1
                continue
            record = records.get(config.fingerprint, {})
            sources = set(record.get("sources", ["previous-output"]))
            if allowed_sources is not None and sources.isdisjoint(allowed_sources[lane]):
                continue
            config.sources.update(sources)
            config.lanes.add(lane)
            configs.append(config)
    if rejected:
        LOGGER.warning("PREVIOUS_PARSE_ERROR count=%d", rejected)
    return configs


def find_core(explicit: str | None) -> str:
    candidate = explicit or os.environ.get("SWIFT_SING_BOX") or shutil.which("sing-box")
    if not candidate:
        raise RuntimeError("sing-box was not found; set SWIFT_SING_BOX or --core")
    path = str(Path(candidate).resolve())
    try:
        process = subprocess.run(
            [path, "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("sing-box could not be executed") from exc
    if process.returncode != 0:
        raise RuntimeError("sing-box version check failed")
    return path


def _source_status(results: list[Any]) -> dict[str, str]:
    status = {}
    for result in results:
        if result.error:
            status[result.source.source_id] = result.error
        elif not result.content.strip():
            status[result.source.source_id] = "EMPTY"
        else:
            status[result.source.source_id] = "OK"
    return status


def _jobs(
    candidates: dict[str, list[ProxyConfig]], resolved: set[str]
) -> list[tuple[ProxyConfig, str]]:
    lane_jobs: dict[str, list[tuple[ProxyConfig, str]]] = {"main": [], "white": []}
    seen: set[tuple[str, str]] = set()
    for lane in ("main", "white"):
        for config in candidates[lane]:
            key = (config.fingerprint, lane)
            if config.fingerprint in resolved and key not in seen:
                lane_jobs[lane].append((config, lane))
                seen.add(key)

    # A lane must not inherit the runner conditions at only one end of a long run.
    # This still schedules every lane independently; it only interleaves their order.
    jobs: list[tuple[ProxyConfig, str]] = []
    for index in range(max(map(len, lane_jobs.values()), default=0)):
        for lane in ("main", "white"):
            if index < len(lane_jobs[lane]):
                jobs.append(lane_jobs[lane][index])
    return jobs


def _cloud_lane_counts(
    lane: str,
    candidates: list[ProxyConfig],
    resolved: set[str],
    results: dict[tuple[str, str], TestResult],
    history_eligible: int,
    mac_expected: int,
) -> dict[str, int | float]:
    prefix = f"{lane}_"
    expected = sum(config.fingerprint in resolved for config in candidates)
    tested = sum((config.fingerprint, lane) in results for config in candidates)
    worked = sum(
        results[(config.fingerprint, lane)].worked
        for config in candidates
        if (config.fingerprint, lane) in results
    )
    passed = sum(
        results[(config.fingerprint, lane)].reason is None
        for config in candidates
        if (config.fingerprint, lane) in results
    )
    return {
        prefix + "resolution_failed": len(candidates) - expected,
        prefix + "cloud_expected": expected,
        prefix + "cloud_tested": tested,
        prefix + "cloud_untested": max(0, expected - tested),
        prefix + "cloud_worked": worked,
        prefix + "cloud_pass": passed,
        prefix + "history_eligible": history_eligible,
        prefix + "mac_expected": mac_expected,
        prefix + "cloud_completion_pct": round(tested / expected * 100, 2) if expected else 100.0,
    }


def _tcp_tls_telemetry_counts(
    probe_targets: list[dict[str, Any]],
    results: dict[str, Any],
    eligible_population: int,
) -> dict[str, int | str]:
    statuses = [results.get(f"{target['host']}:{target['port']}") for target in probe_targets]
    tested = [status for status in statuses if isinstance(status, dict)]
    passed = sum(bool(status.get("ok")) for status in tested)
    failed = len(tested) - passed
    expected = len(probe_targets)
    return {
        "tcp_tls_telemetry_population": eligible_population,
        "tcp_tls_telemetry_expected": expected,
        "tcp_tls_telemetry_tested": len(tested),
        "tcp_tls_telemetry_sampling_policy": (
            "top-ranked history-eligible TCP/TLS-capable White configs; max 60"
        ),
        "white_tcp_tls_tested": len(tested),
        "white_tcp_tls_pass": passed,
        "white_tcp_tls_fail": failed,
        "white_tcp_tls_unknown": expected - len(tested),
    }


def _hold(
    root: Path,
    previous_stats: dict[str, Any] | None,
    reason: str,
    details: dict[str, Any],
) -> None:
    diagnostic = {
        "project": "Swift",
        "tagline": "Filter the garbage. Keep what works.",
        "timestamp": utc_now(),
        "published": False,
        "reason": reason,
        **details,
    }
    write_json(root / "data/run-diagnostics.json", diagnostic)
    if previous_stats:
        held_stats = dict(previous_stats)
        held_stats.update(
            {
                "updated_at": diagnostic["timestamp"],
                "published": False,
                "hold_reason": reason,
                "last_run": details,
            }
        )
        write_json(root / "stats.json", held_stats)
    raise RunHeld(reason)


async def run(root: Path, config_path: Path, core_override: str | None = None) -> None:
    settings = load_settings(config_path)
    paths = settings["paths"]
    history_path = root / paths["history"]
    order_path = root / paths["order"]
    stats_path = root / paths["stats"]
    history = load_json(history_path, empty_history())
    order = load_json(order_path, {"main": [], "white": []})
    previous_stats = load_json(stats_path, None)
    history_version = empty_history()["version"]
    if history.get("version") != history_version:
        LOGGER.warning(
            "HISTORY_RESET old_version=%s new_version=%s",
            history.get("version"),
            history_version,
        )
        history = empty_history()
        order = {"main": [], "white": []}

    proxy_specs = source_specs(settings)
    allowed_sources = {
        lane: {spec.name for spec in proxy_specs if lane in spec.lanes}
        for lane in ("main", "white")
    }
    source_results, evidence_results = await asyncio.gather(
        fetch_sources(proxy_specs, float(settings["collection"]["fetch_timeout"])),
        fetch_sources(
            evidence_specs(settings),
            float(settings["white_evidence"]["fetch_timeout"]),
        ),
    )
    try:
        white_evidence = build_evidence(evidence_results)
    except ValueError:
        _hold(
            root,
            previous_stats,
            "WHITE_EVIDENCE_FAILED",
            {"source_status": _source_status(evidence_results)},
        )
    parsed, parse_failures, collected = parse_sources(source_results)
    current_sources: dict[str, set[str]] = {}
    current_source_lanes: dict[str, set[str]] = {}
    for config in parsed:
        current_sources.setdefault(config.fingerprint, set()).update(config.sources)
        current_source_lanes.setdefault(config.fingerprint, set()).update(config.lanes)
    previous_configs = previous_subscription_configs(root, history, allowed_sources)
    parsed.extend(previous_configs)
    unique, duplicate_count = deduplicate(parsed)
    candidate_lanes = {config.fingerprint: set(config.lanes) for config in unique}
    parse_failures["DUPLICATE"] += duplicate_count
    LOGGER.info(
        "collection collected=%d retained=%d parsed=%d unique=%d duplicates=%d",
        collected,
        len(previous_configs),
        len(parsed),
        len(unique),
        duplicate_count,
    )
    successful_sources = sum(not result.error for result in source_results)
    if successful_sources == 0:
        _hold(
            root,
            previous_stats,
            "ALL_SOURCES_FAILED",
            {"source_status": _source_status(source_results)},
        )
    if not unique:
        _hold(
            root,
            previous_stats,
            "NO_VALID_CONFIGS",
            {"collected": collected, "failure_reasons": dict(parse_failures)},
        )

    white_pool = [config for config in unique if "white" in config.lanes]
    resolved_white, white_resolution_failures = await resolve_candidates(
        white_pool, prefer=white_evidence.contains
    )
    resolved_white_fingerprints = {config.fingerprint for config in resolved_white}
    white_signals: dict[str, str] = {}
    for config in white_pool:
        if config.fingerprint not in resolved_white_fingerprints:
            config.lanes.discard("white")
            reason = white_resolution_failures.get(config.fingerprint, "DNS_FAILED")
            parse_failures[f"WHITE_{reason}"] += 1
            continue
        signal = evidence_for(config, white_evidence)
        if signal is None:
            config.lanes.discard("white")
            parse_failures["NOT_WHITELISTED"] += 1
            continue
        white_signals[config.fingerprint] = signal
    LOGGER.info(
        "white evidence candidates=%d eligible=%d cidr_sni=%d cidr=%d sni=%d rejected=%d",
        len(white_pool),
        len(white_signals),
        sum(signal == "cidr+sni" for signal in white_signals.values()),
        sum(signal == "cidr" for signal in white_signals.values()),
        sum(signal == "sni" for signal in white_signals.values()),
        len(white_pool) - len(white_signals),
    )
    if not await preflight_targets(settings["testing"]):
        _hold(root, previous_stats, "TEST_TARGET_OUTAGE", {})

    core_path = find_core(core_override)
    candidates = {
        "main": [config for config in unique if "main" in config.lanes],
        "white": [config for config in unique if "white" in config.lanes],
    }
    candidate_map = {
        config.fingerprint: config
        for lane_configs in candidates.values()
        for config in lane_configs
    }
    already_resolved = [config for config in candidate_map.values() if config.resolved_ip]
    unresolved = [config for config in candidate_map.values() if not config.resolved_ip]
    newly_resolved, resolution_failures = await resolve_candidates(unresolved)
    resolved_configs = [*already_resolved, *newly_resolved]
    resolved = {config.fingerprint for config in resolved_configs}
    parse_failures.update(resolution_failures.values())
    jobs = _jobs(candidates, resolved)
    LOGGER.info(
        "candidates main=%d white=%d jobs=%d resolution_failed=%d (exhaustive)",
        len(candidates["main"]),
        len(candidates["white"]),
        len(jobs),
        len(resolution_failures),
    )
    results_list = await test_candidates(jobs, core_path, settings["testing"])
    results = {(result.fingerprint, result.lane): result for result in results_list}
    resolution_reasons = {**white_resolution_failures, **resolution_failures}
    forensic_dir = root / ".swift-forensics"
    write_jsonl(
        forensic_dir / "population.jsonl",
        (
            population_record(
                config,
                current_sources.get(config.fingerprint, set()),
                current_source_lanes.get(config.fingerprint, set()),
                candidate_lanes[config.fingerprint],
                resolution_reasons.get(config.fingerprint),
                white_signals.get(config.fingerprint),
            )
            for config in sorted(unique, key=lambda item: item.fingerprint)
        ),
    )
    write_jsonl(
        forensic_dir / "cloud-results.jsonl",
        (
            cloud_result_record(
                candidate_map[result.fingerprint],
                result,
                current_sources.get(result.fingerprint, set()),
            )
            for result in sorted(results_list, key=lambda item: (item.fingerprint, item.lane))
        ),
    )
    temp_history = copy.deepcopy(history)
    for config, lane in jobs:
        result = results.get((config.fingerprint, lane))
        if result:
            add_observation(
                temp_history,
                config,
                result,
                int(settings["history"]["window"]),
            )

    quality = settings["quality"]
    ranked_main = rank_configs(
        unique,
        results,
        temp_history,
        "main",
        order.get("main", []),
        float(quality["main_min_score"]),
        float(settings["testing"]["main_min_throughput_bps"]),
    )
    ranked_white = rank_configs(
        unique,
        results,
        temp_history,
        "white",
        order.get("white", []),
        float(quality["white_min_score"]),
        float(settings["testing"]["white_min_throughput_bps"]),
    )
    ranked_white.sort(
        key=lambda item: evidence_priority(white_signals.get(item.config.fingerprint, "")),
        reverse=True,
    )

    white_tcp_tls_results: dict[str, str] = {}
    white_tcp_tls_telemetry = {
        "tcp_tls_telemetry_population": 0,
        "tcp_tls_telemetry_expected": 0,
        "tcp_tls_telemetry_tested": 0,
        "tcp_tls_telemetry_sampling_policy": (
            "top-ranked history-eligible TCP/TLS-capable White configs; max 60"
        ),
        "white_tcp_tls_tested": 0,
        "white_tcp_tls_pass": 0,
        "white_tcp_tls_fail": 0,
        "white_tcp_tls_unknown": 0,
    }
    if ranked_white and os.environ.get("SWIFT_RU_PROBE_URL"):
        top_white = [
            item
            for item in ranked_white
            if item.config.protocol not in {"hysteria", "hysteria2", "tuic"}
        ][:60]
        probe_targets = [
            {
                "host": item.config.resolved_ip or item.config.host,
                "port": item.config.port,
                "sni": _visible_server_name(item.config),
            }
            for item in top_white
        ]
        ru_results: dict[str, Any] = {}
        try:
            ru_results = probe_ru_targets(probe_targets, check_type="tcp_tls") or {}
        except Exception as exc:
            LOGGER.warning("RU_PROBE_FAILED error=%s (telemetry-only, continuing)", exc)

        for item in ranked_white:
            key_id = f"{item.config.resolved_ip or item.config.host}:{item.config.port}"
            if item.config.protocol in {"hysteria", "hysteria2", "tuic"}:
                white_tcp_tls_results[item.config.fingerprint] = "unsupported"
            elif key_id in ru_results:
                status_item = ru_results[key_id]
                white_tcp_tls_results[item.config.fingerprint] = (
                    "pass" if status_item.get("ok") else "fail"
                )
            else:
                white_tcp_tls_results[item.config.fingerprint] = "unknown"

        white_tcp_tls_telemetry = _tcp_tls_telemetry_counts(
            probe_targets,
            ru_results,
            len(
                [
                    item
                    for item in ranked_white
                    if item.config.protocol not in {"hysteria", "hysteria2", "tuic"}
                ]
            ),
        )
        LOGGER.info(
            "white ru_probe telemetry tested=%d passed=%d failed=%d unknown=%d (telemetry-only, no gating)",
            white_tcp_tls_telemetry["white_tcp_tls_tested"],
            white_tcp_tls_telemetry["white_tcp_tls_pass"],
            white_tcp_tls_telemetry["white_tcp_tls_fail"],
            white_tcp_tls_telemetry["white_tcp_tls_unknown"],
        )

    # Save white tcp_tls telemetry for Mac cross-matrix
    write_json(root / "data/ru_probe_white.json", white_tcp_tls_results, compact=True)

    # Pre-Mac handoff: ALL eligible Main and White configs are sent to Mac without truncation
    main = ranked_main
    white = ranked_white

    main_unique = len([c for c in unique if "main" in c.lanes])
    main_history_eligible = len(ranked_main)
    main_mac_expected = len(main)
    main_counts = _cloud_lane_counts(
        "main", candidates["main"], resolved, results, main_history_eligible, main_mac_expected
    )
    main_cloud_expected = int(main_counts["main_cloud_expected"])
    main_cloud_tested = int(main_counts["main_cloud_tested"])
    main_cloud_pass = int(main_counts["main_cloud_pass"])

    white_pool_count = len(white_pool)
    white_evidence_matched = len(white_signals)
    white_history_eligible = len(ranked_white)
    white_mac_expected = len(white)
    white_counts = _cloud_lane_counts(
        "white",
        candidates["white"],
        resolved,
        results,
        white_history_eligible,
        white_mac_expected,
    )
    white_cloud_tested = int(white_counts["white_cloud_tested"])
    white_cloud_pass = int(white_counts["white_cloud_pass"])

    funnel = {
        "main": {
            "main_unique": main_unique,
            **main_counts,
            "main_mac_tested": 0,
            "main_mac_untested": main_mac_expected,
            "main_mac_https_pass": 0,
            "main_mac_r1_pass": 0,
            "main_mac_r2_pass": 0,
            "main_mac_sustained_pass": 0,
            "main_published": 0,
            "main_mac_completion_pct": 0.0,
        },
        "white": {
            "white_pool": white_pool_count,
            "white_evidence_matched": white_evidence_matched,
            **white_counts,
            "white_mac_tested": 0,
            "white_mac_untested": white_mac_expected,
            "white_mac_sustained_pass": 0,
            "white_published": 0,
            "white_mac_completion_pct": 0.0,
            **white_tcp_tls_telemetry,
        },
    }

    selection_stats = {
        "main_unique": main_unique,
        "main_cloud_selected": main_cloud_expected,
        "main_cloud_pass": main_cloud_pass,
        "main_eligible": main_history_eligible,
        "main_pre_mac_selected": main_mac_expected,
        "main_pre_mac_dropped_by_capacity": 0,
        "eligible_not_sent_to_mac": 0,
        "funnel": funnel,
    }
    LOGGER.info(
        "exhaustive selection main: unique=%d cloud_tested=%d cloud_pass=%d eligible=%d -> mac_expected=%d",
        main_unique,
        main_cloud_tested,
        main_cloud_pass,
        main_history_eligible,
        main_mac_expected,
    )
    LOGGER.info(
        "exhaustive selection white: pool=%d evidence=%d cloud_tested=%d cloud_pass=%d eligible=%d -> mac_expected=%d",
        white_pool_count,
        white_evidence_matched,
        white_cloud_tested,
        white_cloud_pass,
        white_history_eligible,
        white_mac_expected,
    )

    alive = alive_for_all(
        resolved_configs,
        results,
        temp_history,
        float(quality["all_min_throughput_bps"]),
    )

    failures = parse_failures + failure_reasons(results_list)
    reason = suspicious_run(
        previous_stats,
        len(main),
        len(white),
        len(results_list),
        failures,
        successful_sources,
    )
    if len(results_list) < len(jobs) * 0.8:
        reason = reason or "GLOBAL_TIMEOUT"
    source_status = _source_status([*source_results, *evidence_results])
    published_evidence = Counter(
        white_signals[item.config.fingerprint]
        for item in white
        if item.config.fingerprint in white_signals
    )

    # Discovery Queue Observability & Age Tracking
    now_iso = utc_now()
    now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    discovery_seen = temp_history.setdefault("discovery_seen", {})
    new_discovered_this_run = 0
    for cfg in unique:
        if cfg.fingerprint not in discovery_seen:
            discovery_seen[cfg.fingerprint] = now_iso
            new_discovered_this_run += 1

    before_configs = history.get("configs", {})
    never_tested_before = [
        cfg
        for cfg in unique
        if cfg.fingerprint not in before_configs
        or not any(
            lane.get("observations")
            for lane in before_configs[cfg.fingerprint].get("lanes", {}).values()
        )
    ]

    tested_fps = {result.fingerprint for result in results_list}
    tested_first_time = [cfg for cfg in never_tested_before if cfg.fingerprint in tested_fps]

    after_configs = temp_history.get("configs", {})
    never_tested_after = [
        cfg
        for cfg in unique
        if cfg.fingerprint not in after_configs
        or not any(
            lane.get("observations")
            for lane in after_configs[cfg.fingerprint].get("lanes", {}).values()
        )
    ]

    ages_hours = []
    for cfg in never_tested_after:
        seen_str = discovery_seen.get(cfg.fingerprint, now_iso)
        try:
            seen_dt = datetime.fromisoformat(seen_str.replace("Z", "+00:00"))
            ages_hours.append(max(0.0, (now_dt - seen_dt).total_seconds() / 3600.0))
        except Exception:
            ages_hours.append(0.0)

    oldest_never_tested_age_hours = round(max(ages_hours), 2) if ages_hours else 0.0
    average_never_tested_age_hours = (
        round(sum(ages_hours) / len(ages_hours), 2) if ages_hours else 0.0
    )
    backlog_change = len(never_tested_after) - len(never_tested_before)
    first_tested_count = len(tested_first_time)
    estimated_runs_to_clear = (
        (len(never_tested_after) + max(1, first_tested_count) - 1) // max(1, first_tested_count)
        if never_tested_after
        else 0
    )
    estimated_hours_to_clear = round(estimated_runs_to_clear * 0.5, 1)

    discovery_stats = {
        "total_never_tested": len(never_tested_after),
        "tested_first_time_this_run": first_tested_count,
        "oldest_never_tested_age_hours": oldest_never_tested_age_hours,
        "average_never_tested_age_hours": average_never_tested_age_hours,
        "new_discovered_this_run": new_discovered_this_run,
        "backlog_change_this_run": backlog_change,
        "estimated_runs_to_clear": estimated_runs_to_clear,
        "estimated_hours_to_clear": estimated_hours_to_clear,
    }

    def _is_ru_target(cfg: ProxyConfig) -> bool:
        rec = after_configs.get(cfg.fingerprint, {})
        geo = None
        for lane in rec.get("lanes", {}).values():
            for observation in reversed(lane.get("observations", [])):
                if observation.get("country"):
                    geo = observation.get("country")
                    break
        return geo == "RU" or cfg.host.endswith(".ru") or "RU" in cfg.remark.upper()

    ru_hy2_pool = [c for c in unique if c.protocol == "hysteria2" and _is_ru_target(c)]
    hy1_pool = [c for c in unique if c.protocol == "hysteria"]

    diagnostics_stats = {
        "ru_hysteria2": {
            "discovered_total": len(ru_hy2_pool),
            "never_tested": sum(1 for c in ru_hy2_pool if c in never_tested_after),
            "first_tested_this_run": sum(1 for c in ru_hy2_pool if c in tested_first_time),
            "global_pass": sum(
                1
                for c in ru_hy2_pool
                if (c.fingerprint, "main") in results and results[(c.fingerprint, "main")].worked
            ),
            "history_eligible": sum(
                1
                for item in ranked_main
                if item.config.protocol == "hysteria2" and _is_ru_target(item.config)
            ),
            "reached_mac": sum(
                1
                for item in main
                if item.config.protocol == "hysteria2" and _is_ru_target(item.config)
            ),
            "mac_pass": 0,
            "published": 0,
        },
        "hysteria_v1": {
            "discovered_total": len(hy1_pool),
            "never_tested": sum(1 for c in hy1_pool if c in never_tested_after),
            "first_tested_this_run": sum(1 for c in hy1_pool if c in tested_first_time),
            "global_pass": sum(
                1
                for c in hy1_pool
                if (c.fingerprint, "main") in results and results[(c.fingerprint, "main")].worked
            ),
            "history_eligible": sum(
                1 for item in ranked_main if item.config.protocol == "hysteria"
            ),
            "reached_mac": sum(1 for item in main if item.config.protocol == "hysteria"),
            "mac_pass": 0,
            "published": 0,
        },
    }

    stats = build_stats(
        updated_at=now_iso,
        collected=collected,
        parsed=len(parsed),
        unique=len(unique),
        tested=len(results_list),
        alive=alive,
        main=main,
        white=white,
        failures=failures,
        source_status=source_status,
        white_evidence={
            "cidr_source": white_evidence.cidr_source,
            "domain_source": white_evidence.domain_source,
            "eligible": len(white_signals),
            "published": dict(sorted(published_evidence.items())),
        },
        published=False,
        previous=previous_stats,
        reason=reason,
        discovery=discovery_stats,
        diagnostics=diagnostics_stats,
        selection=selection_stats,
    )
    if reason:
        write_json(root / "data/run-diagnostics.json", stats)
        write_json(stats_path, stats)
        raise RunHeld(reason)

    stats["stage"] = "cloud_prepared"
    stats["prepared_for_mac"] = {"main": len(main), "white": len(white)}
    write_mac_handoff(root, main, white, alive)
    prune_history(temp_history)
    write_json(history_path, temp_history, compact=True)
    write_json(
        order_path,
        {
            "main": [item.config.fingerprint for item in main],
            "white": [item.config.fingerprint for item in white],
        },
        compact=True,
    )
    write_json(stats_path, stats)
    LOGGER.info(
        "prepared_mac_artifact_main=%d prepared_mac_artifact_white=%d cloud_all=%d",
        len(main),
        len(white),
        len(alive),
    )


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Filter and test public proxy configs")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--core", help="path to the sing-box binary")
    parser.add_argument("--root", default=".")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--check-output", action="store_true")
    parser.add_argument(
        "--legacy-cloud",
        action="store_true",
        help="run the retired non-production Cloud verifier for manual diagnostics",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    root = Path(args.root).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    if args.check_output:
        settings = load_settings(config_path)
        check_outputs(root, int(settings["limits"]["main"]), int(settings["limits"]["white"]))
        LOGGER.info("output sanity checks passed")
        return 0
    if not args.legacy_cloud:
        parser.error("production collection uses swiftproxy.generation; Cloud traffic is retired")
    try:
        asyncio.run(run(root, config_path, args.core))
    except RunHeld as exc:
        LOGGER.error("publish held reason=%s", exc)
        return 2
    except KeyboardInterrupt:
        LOGGER.error("interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(cli())
