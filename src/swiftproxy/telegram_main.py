from __future__ import annotations

import argparse
import asyncio
import copy
import json
import logging
import os
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .output import atomic_write, write_json
from .ru_probe import probe_ru_targets
from .sources import fetch_sources
from .telegram import (
    LOGGER,
    RankedTelegram,
    TelegramProxy,
    TelegramResult,
    add_observation,
    assess_run,
    choose_candidates,
    deduplicate,
    empty_history,
    fastest_proxies,
    parse_proxy_url,
    parse_source_results,
    previous_output_proxies,
    prune_history,
    rank_proxies,
    select_message_targets,
    telegram_source_specs,
    utc_now,
)
from .telegram_testing import resolve_proxies, telegram_control, test_proxies


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid local data file: {path}") from exc


def _previous_order(root: Path, name: str) -> list[str]:
    path = root / "Telegram" / name
    if not path.exists():
        return []
    order = []
    for line in path.read_text().splitlines():
        try:
            order.append(parse_proxy_url(line).fingerprint)
        except ValueError:
            continue
    return order


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(bool(line.strip()) for line in path.read_text().splitlines())


def _write_proxy_file(path: Path, items: list[RankedTelegram]) -> None:
    content = "\n".join(item.proxy.url for item in items)
    atomic_write(path, content + ("\n" if content else ""))


async def _test_with_ru_probe(
    candidates: list[TelegramProxy], testing: dict[str, Any]
) -> tuple[dict[str, TelegramResult], bool]:
    targets = [
        {
            "id": proxy.fingerprint,
            "host": proxy.host,
            "port": proxy.port,
            "secret": proxy.secret,
        }
        for proxy in candidates
    ]
    probe_results = await asyncio.to_thread(
        probe_ru_targets,
        targets,
        "mtproto",
        chunk_size=int(testing["probe_chunk_size"]),
        request_concurrency=int(testing["probe_concurrency"]),
    )
    timestamp = utc_now()
    results: dict[str, TelegramResult] = {}
    for proxy in candidates:
        item = probe_results.get(proxy.fingerprint)
        if item is None:
            # Older deployed probe versions may not echo the opaque id yet.
            item = probe_results.get(f"{proxy.host}:{proxy.port}")
        if item is None:
            continue
        latency = item.get("latency_ms")
        ok = bool(item.get("ok"))
        results[proxy.fingerprint] = TelegramResult(
            proxy.fingerprint,
            timestamp,
            attempts=1,
            successes=1 if ok else 0,
            rtts_ms=[float(latency)] if ok and latency is not None else [],
            reason=None if ok else str(item.get("error") or "PROTOCOL_ERROR")[:64],
        )
    return results, bool(probe_results)


async def run(root: Path, settings: dict[str, Any]) -> int:
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
    validation_complete = len(results) >= len(candidates) * 0.8

    temp_history = copy.deepcopy(history)
    if control_ok and validation_complete:
        for proxy in candidates:
            result = results.get(proxy.fingerprint)
            if result is not None:
                add_observation(temp_history, proxy, result, telegram["history"])

    previous_order = _previous_order(root, "all.txt")
    working, stable_candidates = rank_proxies(candidates, results, temp_history, previous_order)
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
        _write_proxy_file(output_dir / "all.txt", working)
        _write_proxy_file(output_dir / "stable.txt", stable)
        _write_proxy_file(output_dir / "fastest.txt", fastest)
    else:
        for name in ("all.txt", "stable.txt", "fastest.txt"):
            path = output_dir / name
            if not path.exists():
                atomic_write(path, "")

    production = {
        "working": _count_lines(output_dir / "all.txt"),
        "stable": _count_lines(output_dir / "stable.txt"),
        "fastest": _count_lines(output_dir / "fastest.txt"),
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


def check_outputs(root: Path, settings: dict[str, Any]) -> None:
    limits = settings["telegram"]["limits"]
    for name, limit in (
        ("all.txt", None),
        ("stable.txt", int(limits["stable"])),
        ("fastest.txt", int(limits["fastest"])),
    ):
        path = root / "Telegram" / name
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        if limit is not None and len(lines) > limit:
            raise RuntimeError(f"Telegram/{name} exceeds its limit")
        fingerprints = [parse_proxy_url(line).fingerprint for line in lines]
        if len(fingerprints) != len(set(fingerprints)):
            raise RuntimeError(f"Telegram/{name} contains duplicates")
    status = json.loads((root / "Telegram/status.json").read_text())
    if status.get("project") != "Swift":
        raise RuntimeError("Telegram/status.json branding is invalid")


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Filter and test public Telegram MTProto proxies")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--root", default=".")
    parser.add_argument("--check-output", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    root = Path(args.root).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    with config_path.open("rb") as handle:
        settings = tomllib.load(handle)
    if args.check_output:
        check_outputs(root, settings)
        LOGGER.info("Telegram output sanity checks passed")
        return 0
    try:
        return asyncio.run(run(root, settings))
    except KeyboardInterrupt:
        LOGGER.error("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(cli())
