from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from swiftproxy.models import ProxyConfig, RankedConfig


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
        endpoint = f"{item.config.resolved_ip or item.config.host}:{item.config.port}"
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


def ru_quality_score(result: dict[str, Any], observations: list[dict[str, Any]]) -> float:
    passes = sum(bool(item.get("passed")) for item in observations)
    availability = (passes + 1) / (len(observations) + 2)
    consecutive_passes = 0
    for item in reversed(observations):
        if not item.get("passed"):
            break
        consecutive_passes += 1
    latency = float(result.get("latency", {}).get("median_ms") or 2000)
    speed = min(float(result["r1"]["speed_kbps"]), float(result["r2"]["speed_kbps"]))
    return round(
        50 * availability
        + 5 * min(1.0, len(observations) / 3)
        + 5 * min(1.0, consecutive_passes / 2)
        + 15 * max(0.0, 1 - latency / 2000)
        + 20 * min(1.0, speed / 512)
        + 5,
        2,
    )
