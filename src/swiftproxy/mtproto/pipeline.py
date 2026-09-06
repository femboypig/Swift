from __future__ import annotations

import copy
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from swiftproxy.mtproto.history import add_observation, empty_history, prune_history
from swiftproxy.mtproto.files import line_count, previous_order, write_proxy_file
from swiftproxy.mtproto.models import TelegramResult, utc_now
from swiftproxy.mtproto.parsing import (
    deduplicate,
    parse_source_results,
    previous_output_proxies,
    telegram_source_specs,
)
from swiftproxy.mtproto.probe import _test_with_ru_probe
from swiftproxy.mtproto.selection import (
    assess_run,
    choose_candidates,
    fastest_proxies,
    rank_proxies,
    select_message_targets,
)
from swiftproxy.mtproto.testing import resolve_proxies, telegram_control, test_proxies
from swiftproxy.sources import fetch_sources
from swiftproxy.network import validate_interface
from swiftproxy.storage import atomic_write, write_json

LOGGER = logging.getLogger(__name__)


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid local data file: {path}") from exc


async def run(root: Path, settings: dict[str, Any]) -> int:
    if not os.environ.get("SWIFT_RU_PROBE_URL"):
        validate_interface(os.environ.get("SWIFT_BIND_INTERFACE", ""))
    telegram = settings["telegram"]
    paths = telegram["paths"]
    history_path = root / paths["history"]
    status_path = root / paths["status"]
    history = _load_json(history_path, empty_history())
    previous_status = _load_json(status_path, None)
    if history.get("version") != empty_history()["version"]:
        LOGGER.warning("TELEGRAM_HISTORY_RESET old_version=%s", history.get("version"))
        history = empty_history()

    specs = telegram_source_specs(settings)
    source_results = await fetch_sources(specs, float(telegram["collection"]["fetch_timeout"]))
    parsed, failures, source_stats = parse_source_results(source_results)
    parsed.extend(previous_output_proxies(root))
    unique, duplicates = deduplicate(parsed)
    failures["DUPLICATE"] += duplicates
    seed = datetime.now(UTC).strftime("%Y-%m-%dT%H")
    candidates = choose_candidates(
        unique,
        history,
        int(telegram["testing"]["candidate_limit"]),
        seed,
    )
    timestamp = utc_now()
    if os.environ.get("SWIFT_RU_PROBE_URL"):
        results, control_ok = await _test_with_ru_probe(candidates, telegram["testing"])
    else:
        resolved, resolution_failures = await resolve_proxies(candidates)
        failures.update(resolution_failures.values())
        tested = await test_proxies(resolved, telegram["testing"])
        results = {result.fingerprint: result for result in tested}
        for proxy in candidates:
            if proxy.fingerprint in results:
                continue
            reason = resolution_failures.get(proxy.fingerprint)
            if reason:
                results[proxy.fingerprint] = TelegramResult(
                    proxy.fingerprint, timestamp, reason=reason
                )
        control_ok = await telegram_control(telegram["testing"])
    validation_complete = len(results) == len(candidates)

    temp_history = copy.deepcopy(history)
    if control_ok and validation_complete:
        for proxy in candidates:
            result = results.get(proxy.fingerprint)
            if result is not None:
                add_observation(temp_history, proxy, result, telegram["history"])

    order = previous_order(root, "all.txt")
    working, stable_candidates = rank_proxies(candidates, results, temp_history, order)
    stable = [
        item
        for item in stable_candidates
        if item.state == "degraded" or item.score >= float(telegram["quality"]["stable_min_score"])
    ][: int(telegram["limits"]["stable"])]
    fastest = fastest_proxies(working, int(telegram["limits"]["fastest"]))
    source_names = {spec.source_id: spec.name for spec in specs}
    for source_id, values in source_stats.items():
        name = source_names[source_id]
        values["working"] = sum(name in item.proxy.sources for item in working)
    failures.update(result.reason for result in results.values() if result.reason)

    healthy, reason, suspicious_streak = assess_run(
        previous_status,
        successful_sources=sum(
            not result.error and bool(result.content.strip()) for result in source_results
        ),
        expected=len(candidates),
        completed=len(results),
        working=len(working),
        control_ok=control_ok,
        collapse_ratio=float(telegram["failure"]["collapse_ratio"]),
        hold_runs=int(telegram["failure"]["hold_runs"]),
    )
    output_dir = root / "Telegram"
    if healthy:
        write_proxy_file(output_dir / "all.txt", working)
        write_proxy_file(output_dir / "stable.txt", stable)
        write_proxy_file(output_dir / "fastest.txt", fastest)
    else:
        for name in ("all.txt", "stable.txt", "fastest.txt"):
            path = output_dir / name
            if not path.exists():
                atomic_write(path, "")

    production = {
        "working": line_count(output_dir / "all.txt"),
        "stable": line_count(output_dir / "stable.txt"),
        "fastest": line_count(output_dir / "fastest.txt"),
    }
    last_successful_set = (previous_status or {}).get("last_successful_set")
    if healthy and working:
        last_successful_set = timestamp
    status: dict[str, Any] = {
        "project": "Swift",
        "tagline": "Filter the garbage. Keep what works.",
        "updated_at": timestamp,
        "healthy_run": healthy,
        "tested": len(results),
        "working": len(working),
        "stable": len(stable) if healthy else production["stable"],
        "fastest": len(fastest) if healthy else production["fastest"],
        "production": production,
        "control_ok": control_ok,
        "suspicious_streak": suspicious_streak,
        "last_successful_set": last_successful_set,
        "sources": dict(sorted(source_stats.items())),
        "failure_reasons": dict(sorted(failures.items())),
        "selected": select_message_targets(
            working,
            stable,
            fastest,
            int(datetime.now(UTC).timestamp() // (6 * 3600)),
        )
        if healthy
        else {},
    }
    if reason:
        status["failure_reason"] = reason
    write_json(status_path, status)
    if control_ok and validation_complete:
        prune_history(temp_history)
        write_json(history_path, temp_history, compact=True)
    LOGGER.info(
        "telegram published=%s tested=%d working=%d stable=%d fastest=%d reason=%s",
        healthy,
        len(results),
        len(working),
        status["stable"],
        status["fastest"],
        reason or "OK",
    )
    return 0 if healthy else 2
