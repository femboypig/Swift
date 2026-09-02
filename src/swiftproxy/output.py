from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .models import ProxyConfig, RankedConfig, TestResult
from .parsing import SUPPORTED_PROXY_SCHEMES, parse_uri, serialize_uri


HAPP_PROTOCOLS = {"vless", "vmess", "trojan", "ss", "hysteria2"}
PIPELINE_VERSION = 4


def display_name(
    result: TestResult,
    index: int,
    prefix: str,
) -> str:
    country = (result.country or "??").upper()
    flag = "🏴‍☠️"
    if len(country) == 2 and country.isalpha():
        flag = "".join(chr(ord(character) + 127397) for character in country)
    return f"{flag} {country} · {prefix}{index:03d}"


def subscription_lines(items: Iterable[RankedConfig], prefix: str) -> list[str]:
    lines = []
    for index, item in enumerate(items, 1):
        name = display_name(item.result, index, prefix)
        lines.append(serialize_uri(item.config, name))
    return lines


def country_ordered(items: Iterable[RankedConfig]) -> list[RankedConfig]:
    return sorted(
        items,
        key=lambda item: (
            (item.result.country or "ZZ").upper(),
            -item.score,
            item.config.fingerprint,
        ),
    )


def happ_subscription(lines: list[str], title: str, repository: str) -> str:
    metadata = [
        f"#profile-title: {title}",
        "#profile-update-interval: 1",
        f"#profile-web-page-url: {repository}",
    ]
    return "\n".join([*metadata, *lines]) + "\n"


def plain_subscription(lines: list[str]) -> str:
    return "\n".join(lines) + ("\n" if lines else "")


def validated_proxy_lines(lines: Iterable[str], label: str) -> list[str]:
    validated: list[str] = []
    fingerprints: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        scheme = line.partition(":")[0].lower()
        if scheme not in SUPPORTED_PROXY_SCHEMES:
            raise RuntimeError(f"{label} contains a non-proxy URL")
        try:
            config = parse_uri(line)
        except ValueError as exc:
            raise RuntimeError(f"{label} contains an invalid proxy URI") from exc
        if config.fingerprint in fingerprints:
            raise RuntimeError(f"{label} contains duplicates")
        fingerprints.add(config.fingerprint)
        validated.append(line)
    return validated


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
            key=lambda item: (
                item.success_ratio,
                item.throughput_bps or 0,
                -(item.median_latency_ms or 1e9),
            ),
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
    white_evidence: dict[str, Any] | None = None,
    previous: dict[str, Any] | None = None,
    reason: str | None = None,
    discovery: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    protocols = Counter(item.config.protocol for item in alive)
    sources = Counter(source for item in alive for source in item.config.sources)
    countries = Counter(item.result.country for item in alive if item.result.country)
    latencies = sorted(
        item.result.median_latency_ms for item in alive if item.result.median_latency_ms is not None
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
    if not published:
        production = (
            previous.get(
                "production",
                {
                    "main": int(previous.get("main", 0)),
                    "white": int(previous.get("white", 0)),
                    "all": int(previous.get("alive", 0)),
                },
            )
            if previous
            else {"main": 0, "white": 0, "all": 0}
        )
    value: dict[str, Any] = {
        "project": "Swift",
        "tagline": "Filter the garbage. Keep what works.",
        "pipeline_version": PIPELINE_VERSION,
        "updated_at": updated_at,
        "collection_updated_at": updated_at,
        "publication_updated_at": None,
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
        "white_evidence": white_evidence or {},
        "failure_reasons": dict(sorted(failures.items())),
    }
    if selection:
        value["selection"] = selection
        if "funnel" in selection:
            value["funnel"] = selection["funnel"]
    if discovery:
        value["discovery"] = discovery
    if diagnostics:
        value["diagnostics"] = diagnostics
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


def write_final_subscriptions(
    root: Path,
    main_lines: Iterable[str],
    white_lines: Iterable[str],
    repository: str,
) -> None:
    main = validated_proxy_lines(main_lines, "final Main subscription")
    white = validated_proxy_lines(white_lines, "final White subscription")
    happ_main = [line for line in main if parse_uri(line).protocol in HAPP_PROTOCOLS]
    happ_white = [line for line in white if parse_uri(line).protocol in HAPP_PROTOCOLS]
    outputs = {
        root / "sub/main.txt": plain_subscription(main),
        root / "sub/white.txt": plain_subscription(white),
        root / "sub/happ/main.txt": happ_subscription(happ_main, "Swift Main", repository),
        root / "sub/happ/white.txt": happ_subscription(happ_white, "Swift White", repository),
    }

    previous = {path: path.read_text() if path.exists() else None for path in outputs}
    try:
        for path, content in outputs.items():
            atomic_write(path, content)
    except BaseException:
        for path, content in previous.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, content)
        raise


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
    main_lines = subscription_lines(main, "")
    white_lines = subscription_lines(white, "W")
    all_lines = subscription_lines(alive, "A")
    atomic_write(root / "sub/main.txt", plain_subscription(main_lines))
    atomic_write(root / "sub/white.txt", plain_subscription(white_lines))
    atomic_write(root / "sub/all.txt", plain_subscription(all_lines))

    main_happ = [
        line
        for item, line in zip(main, main_lines, strict=True)
        if item.config.protocol in HAPP_PROTOCOLS
    ]
    white_happ = [
        line
        for item, line in zip(white, white_lines, strict=True)
        if item.config.protocol in HAPP_PROTOCOLS
    ]
    atomic_write(
        root / "sub/happ/main.txt",
        happ_subscription(main_happ, "Swift Main", repository),
    )
    atomic_write(
        root / "sub/happ/white.txt",
        happ_subscription(white_happ, "Swift White", repository),
    )


def write_mac_handoff(
    root: Path,
    main: list[RankedConfig],
    white: list[RankedConfig],
    alive: list[RankedConfig],
) -> None:
    main_lines = validated_proxy_lines(subscription_lines(main, ""), "Mac Main handoff")
    white_lines = validated_proxy_lines(subscription_lines(white, "W"), "Mac White handoff")
    all_lines = validated_proxy_lines(subscription_lines(alive, "A"), "All subscription")
    atomic_write(root / "data/mac-candidates/main.txt", plain_subscription(main_lines))
    atomic_write(root / "data/mac-candidates/white.txt", plain_subscription(white_lines))
    atomic_write(root / "sub/all.txt", plain_subscription(all_lines))


def check_outputs(root: Path, main_limit: int, white_limit: int) -> None:
    for relative, limit in (("sub/main.txt", main_limit), ("sub/white.txt", white_limit)):
        lines = validated_proxy_lines((root / relative).read_text().splitlines(), relative)
        if len(lines) > limit:
            raise RuntimeError(f"{relative} exceeds its limit")
    validated_proxy_lines((root / "sub/all.txt").read_text().splitlines(), "sub/all.txt")
    for relative in ("sub/happ/main.txt", "sub/happ/white.txt"):
        lines = [
            line.strip() for line in (root / relative).read_text().splitlines() if line.strip()
        ]
        if not lines or not lines[0].startswith("#profile-title: Swift"):
            raise RuntimeError(f"{relative} has no Swift metadata")
        proxy_lines = validated_proxy_lines(lines, relative)
        for line in proxy_lines:
            if parse_uri(line).protocol not in HAPP_PROTOCOLS:
                raise RuntimeError(f"{relative} contains a protocol Happ does not document")

        lane = "main" if relative.endswith("main.txt") else "white"
        universal = validated_proxy_lines(
            (root / f"sub/{lane}.txt").read_text().splitlines(),
            f"sub/{lane}.txt",
        )
        expected = [
            parse_uri(line).fingerprint
            for line in universal
            if parse_uri(line).protocol in HAPP_PROTOCOLS
        ]
        actual = [parse_uri(line).fingerprint for line in proxy_lines]
        if actual != expected:
            raise RuntimeError(f"{relative} does not match the compatible {lane} population")
    stats = json.loads((root / "stats.json").read_text())
    if (
        stats.get("project") != "Swift"
        or stats.get("tagline") != "Filter the garbage. Keep what works."
    ):
        raise RuntimeError("stats.json branding is invalid")

    main_lines = [
        line
        for line in (root / "sub/main.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    white_lines = [
        line
        for line in (root / "sub/white.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    prod_stats = stats.get("production", {})
    if prod_stats.get("main") is not None and len(main_lines) != prod_stats["main"]:
        raise RuntimeError(
            f"sub/main.txt count ({len(main_lines)}) != stats.production.main ({prod_stats['main']})"
        )
    if prod_stats.get("white") is not None and len(white_lines) != prod_stats["white"]:
        raise RuntimeError(
            f"sub/white.txt count ({len(white_lines)}) != stats.production.white ({prod_stats['white']})"
        )

    mac_stats = stats.get("mac_verification")
    if mac_stats:
        mac_main = mac_stats.get("main", {})
        if mac_main.get("final") is not None and len(main_lines) != mac_main["final"]:
            raise RuntimeError(
                f"sub/main.txt count ({len(main_lines)}) != stats.mac_verification.main.final ({mac_main['final']})"
            )
        if mac_main.get("mac_pass") is not None:
            if mac_main["mac_pass"] <= main_limit and len(main_lines) != mac_main["mac_pass"]:
                raise RuntimeError(
                    f"sub/main.txt count ({len(main_lines)}) != stats.mac_verification.main.mac_pass ({mac_main['mac_pass']})"
                )
            if mac_main["mac_pass"] > main_limit and len(main_lines) != main_limit:
                raise RuntimeError(
                    f"sub/main.txt count ({len(main_lines)}) != main_limit ({main_limit})"
                )

        mac_white = mac_stats.get("white", {})
        if mac_white.get("final") is not None and len(white_lines) != mac_white["final"]:
            raise RuntimeError(
                f"sub/white.txt count ({len(white_lines)}) != stats.mac_verification.white.final ({mac_white['final']})"
            )
        if mac_white.get("mac_pass") is not None:
            if mac_white["mac_pass"] <= white_limit and len(white_lines) != mac_white["mac_pass"]:
                raise RuntimeError(
                    f"sub/white.txt count ({len(white_lines)}) != stats.mac_verification.white.mac_pass ({mac_white['mac_pass']})"
                )
            if mac_white["mac_pass"] > white_limit and len(white_lines) != white_limit:
                raise RuntimeError(
                    f"sub/white.txt count ({len(white_lines)}) != white_limit ({white_limit})"
                )
