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
    write_subscriptions,
)
from .parsing import deduplicate, parse_sources
from .scoring import (
    add_observation,
    choose_candidates,
    diverse_selection,
    empty_history,
    failure_reasons,
    prune_history,
    rank_configs,
)
from .sources import fetch_sources, source_specs
from .testing import preflight_targets, resolve_candidates, test_candidates


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
    jobs = []
    seen: set[tuple[str, str]] = set()
    for lane in ("main", "white"):
        for config in candidates[lane]:
            key = (config.fingerprint, lane)
            if config.fingerprint in resolved and key not in seen:
                jobs.append((config, lane))
                seen.add(key)
    return jobs


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

    source_results = await fetch_sources(
        source_specs(settings), float(settings["collection"]["fetch_timeout"])
    )
    parsed, parse_failures, collected = parse_sources(source_results)
    unique, duplicate_count = deduplicate(parsed)
    parse_failures["DUPLICATE"] += duplicate_count
    LOGGER.info(
        "collection collected=%d parsed=%d unique=%d duplicates=%d",
        collected,
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
    if not await preflight_targets(settings["testing"]):
        _hold(root, previous_stats, "TEST_TARGET_OUTAGE", {})

    core_path = find_core(core_override)
    selection = settings["selection"]
    seed = datetime.now(UTC).strftime("%Y-%m-%dT%H")
    candidates = {
        "main": choose_candidates(
            unique, history, "main", int(selection["main_candidates"]), seed
        ),
        "white": choose_candidates(
            unique, history, "white", int(selection["white_candidates"]), seed
        ),
    }
    candidate_map = {
        config.fingerprint: config
        for lane_configs in candidates.values()
        for config in lane_configs
    }
    resolved_configs, resolution_failures = await resolve_candidates(list(candidate_map.values()))
    resolved = {config.fingerprint for config in resolved_configs}
    parse_failures.update(resolution_failures.values())
    jobs = _jobs(candidates, resolved)
    LOGGER.info(
        "candidates main=%d white=%d jobs=%d resolution_failed=%d",
        len(candidates["main"]),
        len(candidates["white"]),
        len(jobs),
        len(resolution_failures),
    )
    results_list = await test_candidates(jobs, core_path, settings["testing"])
    results = {(result.fingerprint, result.lane): result for result in results_list}
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
        float(settings["testing"]["min_throughput_bps"]),
    )
    ranked_white = rank_configs(
        unique,
        results,
        temp_history,
        "white",
        order.get("white", []),
        float(quality["white_min_score"]),
        float(settings["testing"]["min_throughput_bps"]),
    )
    diversity = settings["diversity"]
    main = diverse_selection(
        ranked_main,
        int(settings["limits"]["main"]),
        int(diversity["endpoint"]),
        int(diversity["subnet"]),
        int(diversity["asn"]),
    )
    white = diverse_selection(
        ranked_white,
        int(settings["limits"]["white"]),
        int(diversity["endpoint"]),
        int(diversity["subnet"]),
        int(diversity["asn"]),
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
    source_status = _source_status(source_results)
    stats = build_stats(
        updated_at=utc_now(),
        collected=collected,
        parsed=len(parsed),
        unique=len(unique),
        tested=len(results_list),
        alive=alive,
        main=main,
        white=white,
        failures=failures,
        source_status=source_status,
        published=reason is None,
        previous=previous_stats,
        reason=reason,
    )
    if reason:
        write_json(root / "data/run-diagnostics.json", stats)
        write_json(stats_path, stats)
        raise RunHeld(reason)

    write_subscriptions(
        root,
        main,
        white,
        alive,
        settings["project"]["repository"],
    )
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
    LOGGER.info("published main=%d white=%d all=%d", len(main), len(white), len(alive))


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Filter and test public proxy configs")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--core", help="path to the sing-box binary")
    parser.add_argument("--root", default=".")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--check-output", action="store_true")
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
