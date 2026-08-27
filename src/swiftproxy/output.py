from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .models import ProxyConfig, RankedConfig, TestResult
from .parsing import serialize_uri


HAPP_PROTOCOLS = {"vless", "vmess", "trojan", "ss", "hysteria2"}
PIPELINE_VERSION = 2


def display_name(
    config: ProxyConfig,
    result: TestResult,
) -> str:
    parts = [config.label, config.fingerprint[:6].upper()]
    if result.country:
        parts.insert(0, result.country)
    return " | ".join(parts)


def subscription_lines(items: Iterable[RankedConfig]) -> list[str]:
    lines = []
    for item in items:
        name = display_name(item.config, item.result)
        lines.append(serialize_uri(item.config, name))
    return lines


def happ_subscription(lines: list[str], title: str, repository: str) -> str:
    metadata = [
        f"#profile-title: {title}",
        "#profile-update-interval: 1",
        f"#profile-web-page-url: {repository}",
    ]
    return "\n".join([*metadata, *lines]) + "\n"


def plain_subscription(lines: list[str]) -> str:
    return "\n".join(lines) + ("\n" if lines else "")


def alive_for_all(
    configs: list[ProxyConfig],
    results: dict[tuple[str, str], TestResult],
    history: dict[str, Any],
    min_throughput: float,
) -> list[RankedConfig]:
    alive: list[RankedConfig] = []
    for config in configs:
        available = [
            result
            for lane in ("main", "white")
            if (result := results.get((config.fingerprint, lane))) is not None
            and result.confirmed
            and (result.throughput_bps or 0) >= min_throughput
        ]
        if not available:
            continue
        result = max(
            available,
            key=lambda item: (item.success_ratio, item.throughput_bps or 0, -(item.median_latency_ms or 1e9)),
        )
        lane_record = (
            history.get("configs", {})
            .get(config.fingerprint, {})
            .get("lanes", {})
            .get(result.lane, {})
        )
        observations = lane_record.get("observations", [])
        availability = 0.0
        if observations:
            availability = sum(float(item.get("success_ratio", 0)) for item in observations) / len(
                observations
            )
        alive.append(
            RankedConfig(
                config=config,
                lane=result.lane,
                result=result,
                score=float(lane_record.get("score", 0)),
                state=str(lane_record.get("state", "new")),
                availability=availability,
            )
        )
    alive.sort(key=lambda item: (item.config.protocol, item.config.fingerprint))
    return alive


def build_stats(
    *,
    updated_at: str,
    collected: int,
    parsed: int,
    unique: int,
    tested: int,
    alive: list[RankedConfig],
    main: list[RankedConfig],
    white: list[RankedConfig],
    failures: Counter[str],
    source_status: dict[str, str],
    published: bool,
    previous: dict[str, Any] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    protocols = Counter(item.config.protocol for item in alive)
    countries = Counter(item.result.country or "??" for item in alive)
    sources: Counter[str] = Counter()
    for item in alive:
        sources.update(item.config.sources)
    latencies = sorted(
        item.result.median_latency_ms
        for item in alive
        if item.result.median_latency_ms is not None
    )
    median_latency = None
    if latencies:
        middle = len(latencies) // 2
        median_latency = (
            latencies[middle]
            if len(latencies) % 2
            else (latencies[middle - 1] + latencies[middle]) / 2
        )
    production = {
        "main": len(main),
        "white": len(white),
        "all": len(alive),
    }
    if not published and previous:
        production = previous.get(
            "production",
            {
                "main": int(previous.get("main", 0)),
                "white": int(previous.get("white", 0)),
                "all": int(previous.get("alive", 0)),
            },
        )
    value: dict[str, Any] = {
        "project": "Swift",
        "tagline": "Filter the garbage. Keep what works.",
        "pipeline_version": PIPELINE_VERSION,
        "updated_at": updated_at,
        "published": published,
        "collected": collected,
        "parsed": parsed,
        "unique": unique,
        "tested": tested,
        "alive": len(alive),
        "main": len(main),
        "white": len(white),
        "production": production,
        "median_latency_ms": round(median_latency, 2) if median_latency is not None else None,
        "protocols": dict(sorted(protocols.items())),
        "sources": dict(sorted(sources.items())),
        "countries": dict(sorted(countries.items())),
        "source_status": dict(sorted(source_status.items())),
        "failure_reasons": dict(sorted(failures.items())),
    }
    if reason:
        value["hold_reason"] = reason
    return value


def suspicious_run(
    previous: dict[str, Any] | None,
    main_count: int,
    white_count: int,
    tested: int,
    failures: Counter[str],
    successful_sources: int,
) -> str | None:
    if successful_sources == 0:
        return "ALL_SOURCES_FAILED"
    if tested >= 20 and failures["CORE_START_FAILED"] / tested >= 0.6:
        return "CORE_FAILURE_RATE"
    if not previous or previous.get("pipeline_version") != PIPELINE_VERSION:
        return None
    production = previous.get("production", {})
    previous_main = int(production.get("main", previous.get("main", 0)))
    previous_white = int(production.get("white", previous.get("white", 0)))
    if previous_main >= 20 and main_count < max(8, int(previous_main * 0.25)):
        return "MAIN_MASS_FAILURE"
    if previous_white >= 20 and white_count < max(8, int(previous_white * 0.20)):
        return "WHITE_MASS_FAILURE"
    return None


def atomic_write(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return False
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def write_json(path: Path, value: Any, *, compact: bool = False) -> bool:
    content = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        if compact
        else json.dumps(value, indent=2, sort_keys=True) + "\n"
    )
    return atomic_write(path, content)


def write_subscriptions(
    root: Path,
    main: list[RankedConfig],
    white: list[RankedConfig],
    alive: list[RankedConfig],
    repository: str,
) -> None:
    main_lines = subscription_lines(main)
    white_lines = subscription_lines(white)
    all_lines = subscription_lines(alive)
    atomic_write(root / "sub/main.txt", plain_subscription(main_lines))
    atomic_write(root / "sub/white.txt", plain_subscription(white_lines))
    atomic_write(root / "sub/all.txt", plain_subscription(all_lines))

    main_happ = [
        line for item, line in zip(main, main_lines, strict=True) if item.config.protocol in HAPP_PROTOCOLS
    ]
    white_happ = [
        line for item, line in zip(white, white_lines, strict=True) if item.config.protocol in HAPP_PROTOCOLS
    ]
    atomic_write(
        root / "sub/happ/main.txt",
        happ_subscription(main_happ, "Swift Main", repository),
    )
    atomic_write(
        root / "sub/happ/white.txt",
        happ_subscription(white_happ, "Swift White", repository),
    )


def check_outputs(root: Path, main_limit: int, white_limit: int) -> None:
    from .parsing import parse_uri

    for relative, limit in (("sub/main.txt", main_limit), ("sub/white.txt", white_limit)):
        lines = [line.strip() for line in (root / relative).read_text().splitlines() if line.strip()]
        if len(lines) > limit:
            raise RuntimeError(f"{relative} exceeds its limit")
        fingerprints = [parse_uri(line).fingerprint for line in lines]
        if len(fingerprints) != len(set(fingerprints)):
            raise RuntimeError(f"{relative} contains duplicates")
    all_lines = [line.strip() for line in (root / "sub/all.txt").read_text().splitlines() if line.strip()]
    all_fingerprints = [parse_uri(line).fingerprint for line in all_lines]
    if len(all_fingerprints) != len(set(all_fingerprints)):
        raise RuntimeError("sub/all.txt contains duplicates")
    for relative in ("sub/happ/main.txt", "sub/happ/white.txt"):
        lines = [line.strip() for line in (root / relative).read_text().splitlines() if line.strip()]
        if not lines or not lines[0].startswith("#profile-title: Swift"):
            raise RuntimeError(f"{relative} has no Swift metadata")
        for line in lines:
            if line.startswith("#"):
                continue
            if parse_uri(line).protocol not in HAPP_PROTOCOLS:
                raise RuntimeError(f"{relative} contains a protocol Happ does not document")
    stats = json.loads((root / "stats.json").read_text())
    if stats.get("project") != "Swift" or stats.get("tagline") != "Filter the garbage. Keep what works.":
        raise RuntimeError("stats.json branding is invalid")
