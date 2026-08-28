from __future__ import annotations

import hashlib
import ipaddress
import math
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import ProxyConfig, RankedConfig, TestResult


def empty_history() -> dict[str, Any]:
    return {"version": 3, "configs": {}}


def _lane_record(history: dict[str, Any], fingerprint: str, lane: str) -> dict[str, Any]:
    record = history.get("configs", {}).get(fingerprint, {})
    return record.get("lanes", {}).get(lane, {})


def choose_candidates(
    configs: list[ProxyConfig],
    history: dict[str, Any],
    lane: str,
    limit: int,
    seed: str,
) -> list[ProxyConfig]:
    eligible = [config for config in configs if lane in config.lanes]

    def key(config: ProxyConfig) -> tuple[int, float, str]:
        record = _lane_record(history, config.fingerprint, lane)
        state = record.get("state", "new")
        if state == "active":
            tier = 0
        elif record.get("score", 0) >= 68:
            tier = 1
        elif state == "degraded":
            tier = 2
        elif not record:
            tier = 3
        else:
            tier = 4
        lottery = hashlib.sha256(f"{seed}:{lane}:{config.fingerprint}".encode()).hexdigest()
        return tier, -float(record.get("score", 0)), lottery

    eligible.sort(key=key)
    return eligible[:limit]


def add_observation(
    history: dict[str, Any],
    config: ProxyConfig,
    result: TestResult,
    window: int,
) -> dict[str, Any]:
    configs = history.setdefault("configs", {})
    record = configs.setdefault(
        config.fingerprint,
        {"protocol": config.protocol, "sources": [], "lanes": {}},
    )
    record["protocol"] = config.protocol
    record["sources"] = sorted(config.sources)
    record["last_seen"] = result.timestamp
    lane = record.setdefault("lanes", {}).setdefault(result.lane, {"observations": []})
    previous_state = lane.get("state", "new")
    lane.setdefault("observations", []).append(result.observation())
    lane["observations"] = lane["observations"][-window:]
    lane["state"] = state_after(previous_state, lane["observations"], result)
    return lane


def state_after(previous: str, observations: list[dict[str, Any]], result: TestResult) -> str:
    if result.confirmed and result.success_ratio >= 0.8:
        return "active"
    consecutive_failures = 0
    for observation in reversed(observations):
        if _observation_availability(observation) >= 0.8:
            break
        consecutive_failures += 1
    if previous == "active" and consecutive_failures <= 1:
        return "degraded"
    if result.success_ratio >= 0.6 and previous != "new":
        return "degraded"
    if consecutive_failures >= 2 or previous == "dead":
        return "dead"
    return "new" if previous == "new" else "degraded"


def _observation_availability(observation: dict[str, Any]) -> float:
    ratio = float(observation.get("success_ratio", int(observation.get("success", False))))
    rounds = int(observation.get("rounds", 0))
    if rounds:
        confirmed = int(observation.get("confirmed_rounds", 0))
        ratio *= confirmed / rounds
    return ratio


def _weighted_availability(observations: list[dict[str, Any]]) -> float:
    if not observations:
        return 0.0
    weighted = 0.0
    total = 0.0
    for age, observation in enumerate(reversed(observations)):
        weight = 0.86**age
        weighted += _observation_availability(observation) * weight
        total += weight
    return weighted / total


def _linear_score(value: float | None, good: float, bad: float) -> float:
    if value is None:
        return 0.0
    if value <= good:
        return 1.0
    if value >= bad:
        return 0.0
    return 1.0 - (value - good) / (bad - good)


def _freshness(observations: list[dict[str, Any]], now: datetime) -> float:
    successful = next(
        (item for item in reversed(observations) if _observation_availability(item) >= 0.8),
        None,
    )
    if not successful:
        return 0.0
    try:
        seen = datetime.fromisoformat(successful["timestamp"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return 0.0
    hours = max(0.0, (now - seen).total_seconds() / 3600)
    return max(0.0, 1.0 - hours / 24.0)


def score_lane(
    lane_record: dict[str, Any],
    now: datetime | None = None,
    lane: str = "main",
) -> tuple[float, float]:
    observations = lane_record.get("observations", [])
    if not observations:
        return 0.0, 0.0
    now = now or datetime.now(UTC)
    availability = _weighted_availability(observations)
    current = observations[-1]
    metrics = current
    if _observation_availability(current) < 0.8:
        metrics = next(
            (item for item in reversed(observations) if _observation_availability(item) >= 0.8),
            current,
        )
    recent = sum(_observation_availability(item) for item in observations[-3:]) / min(
        3, len(observations)
    )
    latency = _linear_score(metrics.get("median_latency"), 80, 1400)
    tail = _linear_score(metrics.get("p95_latency"), 140, 2200)
    jitter = _linear_score(metrics.get("jitter"), 25, 700)
    throughput = metrics.get("throughput")
    if throughput is None:
        throughput_score = 0.0
    else:
        throughput_score = min(1.0, math.log2(max(float(throughput), 32768) / 32768) / 6)
    freshness = _freshness(observations, now)

    if lane == "white":
        # Actions latency is a poor signal for configs meant for restricted Russian networks.
        score = 100 * (
            0.50 * availability
            + 0.30 * recent
            + 0.10 * throughput_score
            + 0.10 * freshness
        )
    else:
        score = 100 * (
            0.34 * availability
            + 0.21 * recent
            + 0.14 * latency
            + 0.08 * tail
            + 0.08 * jitter
            + 0.10 * throughput_score
            + 0.05 * freshness
        )
    return round(score, 2), availability


def rank_configs(
    configs: list[ProxyConfig],
    results: dict[tuple[str, str], TestResult],
    history: dict[str, Any],
    lane: str,
    previous_order: list[str],
    min_score: float,
    min_throughput: float,
) -> list[RankedConfig]:
    previous_index = {fingerprint: index for index, fingerprint in enumerate(previous_order)}
    ranked: list[RankedConfig] = []
    for config in configs:
        result = results.get((config.fingerprint, lane))
        if result is None:
            continue
        lane_record = _lane_record(history, config.fingerprint, lane)
        previous_score = float(lane_record.get("score", 0))
        score, availability = score_lane(lane_record, lane=lane)
        state = lane_record.get("state", "new")
        previous_success = next(
            (item for item in reversed(lane_record.get("observations", [])) if item.get("success")),
            {},
        )
        if result.country is None:
            result.country = previous_success.get("country")
        if result.asn is None:
            result.asn = previous_success.get("asn")
        if result.provider is None:
            result.provider = previous_success.get("provider")
        current_ok = (
            result.confirmed
            and result.success_ratio >= 0.8
            and (result.throughput_bps or 0) >= min_throughput
        )
        observations = lane_record.get("observations", [])
        one_run_grace = (
            state == "degraded"
            and result.success_count == 0
            and len(observations) > 1
            and _observation_availability(observations[-2]) >= 0.8
        )
        if one_run_grace:
            score = max(score, previous_score - 8)
        lane_record["score"] = score
        if state not in {"active", "degraded"}:
            continue
        if score < min_score and not one_run_grace:
            continue
        if not current_ok and not one_run_grace:
            continue
        ranked.append(RankedConfig(config, lane, result, score, state, availability))

    ranked.sort(
        key=lambda item: (
            -math.floor(item.score),
            previous_index.get(item.config.fingerprint, 1_000_000),
            item.config.fingerprint,
        )
    )
    return ranked


def _subnet(config: ProxyConfig) -> str:
    value = config.resolved_ip or config.host
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def diverse_selection(
    ranked: list[RankedConfig],
    limit: int,
    endpoint_limit: int,
    subnet_limit: int,
    asn_limit: int,
) -> list[RankedConfig]:
    selected: list[RankedConfig] = []
    deferred: list[RankedConfig] = []
    endpoints: Counter[str] = Counter()
    subnets: Counter[str] = Counter()
    asns: Counter[int] = Counter()
    for item in ranked:
        endpoint = item.config.endpoint
        subnet = _subnet(item.config)
        asn = item.result.asn
        crowded = endpoints[endpoint] >= endpoint_limit or subnets[subnet] >= subnet_limit
        if asn is not None and asns[asn] >= asn_limit:
            crowded = True
        if crowded:
            deferred.append(item)
            continue
        selected.append(item)
        endpoints[endpoint] += 1
        subnets[subnet] += 1
        if asn is not None:
            asns[asn] += 1
        if len(selected) == limit:
            return selected
    for item in deferred:
        if len(selected) == limit:
            break
        selected.append(item)
    return selected


def failure_reasons(results: list[TestResult]) -> Counter[str]:
    return Counter(result.reason for result in results if result.reason)


def prune_history(history: dict[str, Any], max_configs: int = 50_000) -> None:
    configs = history.get("configs", {})
    cutoff = datetime.now(UTC) - timedelta(days=14)
    stale = []
    for fingerprint, record in configs.items():
        try:
            last_seen = datetime.fromisoformat(str(record.get("last_seen", "")).replace("Z", "+00:00"))
        except ValueError:
            last_seen = datetime.min.replace(tzinfo=UTC)
        states = {lane.get("state") for lane in record.get("lanes", {}).values()}
        if last_seen < cutoff and not states.intersection({"active", "degraded"}):
            stale.append(fingerprint)
    for fingerprint in stale:
        configs.pop(fingerprint, None)
    if len(configs) <= max_configs:
        return
    oldest = sorted(
        configs,
        key=lambda fingerprint: str(configs[fingerprint].get("last_seen", "")),
    )
    removable = [
        fingerprint
        for fingerprint in oldest
        if not {
            lane.get("state") for lane in configs[fingerprint].get("lanes", {}).values()
        }.intersection({"active", "degraded"})
    ]
    for fingerprint in removable[: max(0, len(configs) - max_configs)]:
        configs.pop(fingerprint, None)
