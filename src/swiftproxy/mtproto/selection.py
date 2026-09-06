from __future__ import annotations

import hashlib
import math
from typing import Any

from swiftproxy.mtproto.history import _availability, _is_strong
from swiftproxy.mtproto.models import RankedTelegram, TelegramProxy, TelegramResult


def choose_candidates(
    proxies: list[TelegramProxy], history: dict[str, Any], limit: int, seed: str
) -> list[TelegramProxy]:
    records = history.get("proxies", {})

    def key(proxy: TelegramProxy) -> tuple[int, float, str]:
        record = records.get(proxy.fingerprint, {})
        state = record.get("state", "new")
        if state == "active":
            tier = 0
        elif state == "degraded":
            tier = 1
        elif float(record.get("score", 0)) >= 65:
            tier = 2
        elif not record:
            tier = 3
        else:
            tier = 4
        lottery = hashlib.sha256(f"{seed}:{proxy.fingerprint}".encode()).hexdigest()
        return tier, -float(record.get("score", 0)), lottery

    return sorted(proxies, key=key)[:limit]


def _linear(value: float | None, good: float, bad: float) -> float:
    if value is None:
        return 0.0
    if value <= good:
        return 1.0
    if value >= bad:
        return 0.0
    return 1 - (value - good) / (bad - good)


def score_proxy(record: dict[str, Any], secret_kind: str) -> tuple[float, float]:
    observations = record.get("observations", [])
    if not observations:
        return 0.0, 0.0
    weighted = 0.0
    total_weight = 0.0
    for age, observation in enumerate(reversed(observations)):
        weight = 0.88**age
        weighted += _availability(observation) * weight
        total_weight += weight
    availability = weighted / total_weight
    recent = sum(_availability(item) for item in observations[-3:]) / min(3, len(observations))
    metrics = next((item for item in reversed(observations) if _is_strong(item)), {})
    median = _linear(metrics.get("median_rtt"), 120, 2500)
    p95 = _linear(metrics.get("p95_rtt"), 180, 4000)
    jitter = _linear(metrics.get("jitter"), 30, 1500)
    useful = {"faketls": 1.0, "secure": 0.8, "raw": 0.6}.get(secret_kind, 0.0)
    fresh = 1.0 if observations[-1].get("fresh_source") else 0.0
    score = 100 * (
        0.45 * availability
        + 0.18 * median
        + 0.08 * p95
        + 0.07 * jitter
        + 0.12 * recent
        + 0.05 * useful
        + 0.05 * fresh
    )
    return round(score, 2), availability


def rank_proxies(
    proxies: list[TelegramProxy],
    results: dict[str, TelegramResult],
    history: dict[str, Any],
    previous_order: list[str],
) -> tuple[list[RankedTelegram], list[RankedTelegram]]:
    previous_index = {fingerprint: index for index, fingerprint in enumerate(previous_order)}
    working: list[RankedTelegram] = []
    stable: list[RankedTelegram] = []
    records = history.get("proxies", {})
    for proxy in proxies:
        result = results.get(proxy.fingerprint)
        if result is None:
            continue
        record = records.get(proxy.fingerprint, {})
        previous_score = float(record.get("score", 0))
        score, availability = score_proxy(record, proxy.secret_kind)
        if record.get("state") == "degraded":
            score = max(score, previous_score - 6)
        record["score"] = score
        ranked = RankedTelegram(proxy, result, score, str(record.get("state", "new")), availability)
        if result.working:
            working.append(ranked)
        if ranked.state in {"active", "degraded"}:
            stable.append(ranked)

    def quality_key(item: RankedTelegram) -> tuple[int, int, str]:
        return (
            -math.floor(item.score),
            previous_index.get(item.proxy.fingerprint, 1_000_000),
            item.proxy.fingerprint,
        )

    working.sort(key=quality_key)
    stable.sort(key=quality_key)
    return working, stable


def fastest_proxies(working: list[RankedTelegram], limit: int) -> list[RankedTelegram]:
    def key(item: RankedTelegram) -> tuple[float, float, str]:
        median = item.result.median_rtt or 1e9
        tail = max(0.0, (item.result.p95_rtt or median) - median)
        jitter = item.result.jitter or 0.0
        health_penalty = (1 - item.result.success_ratio) * 800
        return (
            median + 0.25 * tail + 0.5 * jitter + health_penalty,
            -item.score,
            item.proxy.fingerprint,
        )

    return sorted(working, key=key)[:limit]


def select_message_targets(
    working: list[RankedTelegram],
    stable: list[RankedTelegram],
    fastest: list[RankedTelegram],
    rotation_slot: int = 0,
) -> dict[str, Any]:
    selected: list[tuple[str, RankedTelegram]] = []

    def suitable(candidates: list[RankedTelegram]) -> list[RankedTelegram]:
        healthy = [
            item
            for item in candidates
            if item.result.attempts >= 3
            and item.result.successes == item.result.attempts
            and (item.result.median_rtt or math.inf) <= 1500
            and (item.result.p95_rtt or math.inf) <= 2500
            and item.result.jitter is not None
            and item.result.jitter <= 700
        ]
        preferred = [
            item
            for item in healthy
            if item.proxy.port == 443 and item.proxy.secret_kind == "faketls"
        ]
        if preferred:
            return preferred
        standard_port = [item for item in healthy if item.proxy.port == 443]
        return standard_port or healthy

    def add(label: str, candidates: list[RankedTelegram], offset: int) -> None:
        used = {item.proxy.fingerprint for _, item in selected}
        candidates = suitable(candidates)
        rotating = candidates[: min(3, len(candidates))]
        if rotating:
            start = (rotation_slot + offset) % len(rotating)
            candidates = rotating[start:] + rotating[:start] + candidates[len(rotating) :]
        choice = next((item for item in candidates if item.proxy.fingerprint not in used), None)
        if choice is not None:
            selected.append((label, choice))

    current_stable = [item for item in stable if item.result.working and item.state == "active"]
    add("fastest", fastest, 0)
    add("stable", current_stable or working, 1)
    add(
        "backup",
        [item for item in working if item.proxy.host not in {x.proxy.host for _, x in selected}],
        2,
    )
    if len(selected) < 3:
        add("backup", working, 2)
    return {
        label: {
            "url": item.proxy.url,
            "score": item.score,
            "median_rtt_ms": item.result.median_rtt,
        }
        for label, item in selected[:3]
    }


def assess_run(
    previous: dict[str, Any] | None,
    *,
    successful_sources: int,
    expected: int,
    completed: int,
    working: int,
    control_ok: bool,
    collapse_ratio: float,
    hold_runs: int,
) -> tuple[bool, str | None, int]:
    previous_streak = int((previous or {}).get("suspicious_streak", 0))
    if successful_sources == 0:
        return False, "ALL_SOURCES_FAILED", previous_streak
    if completed != expected:
        return False, "GLOBAL_TIMEOUT", previous_streak
    if not control_ok:
        return False, "TELEGRAM_CONTROL_FAILED", previous_streak
    production = (previous or {}).get("production", {})
    previous_working = int(production.get("working", (previous or {}).get("working", 0)))
    threshold = max(1, math.floor(previous_working * collapse_ratio))
    collapsed = working < threshold
    if not collapsed:
        return True, None, 0
    streak = previous_streak + 1
    if streak <= hold_runs:
        return False, "MASS_FAILURE", streak
    return True, None, 0
