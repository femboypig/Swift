from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Iterable

from .models import ProxyConfig, TestResult
from .output import atomic_write


SCHEMA_VERSION = 1


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    content = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records
    )
    atomic_write(path, content)


def population_record(
    config: ProxyConfig,
    current_sources: set[str],
    current_source_lanes: set[str],
    candidate_lanes: set[str],
    resolution_reason: str | None,
    white_evidence: str | None,
) -> dict[str, Any]:
    try:
        address_family = f"ipv{ipaddress.ip_address(config.resolved_ip or config.host).version}"
    except ValueError:
        address_family = "hostname"
    resolution_attempted = bool(candidate_lanes.intersection({"main", "white"}))
    resolution_success = config.resolved_ip is not None
    return {
        "schema_version": SCHEMA_VERSION,
        "fingerprint": config.fingerprint,
        "protocol": config.protocol,
        "sources": sorted(current_sources),
        "parsed_present": bool(current_sources),
        "candidate_sources": sorted(config.sources),
        "source_lanes": sorted(current_source_lanes),
        "candidate_lanes": sorted(candidate_lanes),
        "resolution": {
            "attempted": resolution_attempted,
            "success": resolution_success,
            "reason": None if resolution_success else resolution_reason,
            "resolved_ip": config.resolved_ip,
            "port": config.port,
            "address_family": address_family,
        },
        "white": {
            "upstream_label": "white" in current_source_lanes,
            "evidence": white_evidence,
        },
    }


def cloud_result_record(
    config: ProxyConfig,
    result: TestResult,
    current_sources: set[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "fingerprint": config.fingerprint,
        "lane": result.lane,
        "protocol": config.protocol,
        "sources": sorted(config.sources if current_sources is None else current_sources),
        "final_reason": result.reason or "PASS",
        "worked": result.worked,
        "confirmed": result.confirmed,
        "success_count": result.success_count,
        "failure_count": result.failure_count,
        "rounds": result.round_diagnostics,
        "core_start_failures": result.core_start_failures,
    }
