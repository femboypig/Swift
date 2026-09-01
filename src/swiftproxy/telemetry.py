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


def _download_record(attempt: Any) -> dict[str, Any] | None:
    if attempt is None:
        return None
    if attempt.ok:
        category = None
    elif attempt.is_stall:
        category = "STALLED"
    elif isinstance(attempt.error, str) and attempt.error.startswith("EXIT_"):
        category = attempt.error
    else:
        category = "DOWNLOAD_FAILED"
    return {
        "success": bool(attempt.ok),
        "status_code": int(attempt.status_code),
        "bytes": int(attempt.bytes_downloaded),
        "speed_kbps": round(float(attempt.speed_kbps), 2),
        "category": category,
    }


def mac_result_record(
    config: ProxyConfig,
    result: Any,
    sources: set[str],
    lanes: set[str],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "fingerprint": config.fingerprint,
        "protocol": config.protocol,
        "sources": sorted(sources),
        "lanes": sorted(lanes),
        "final_reason": result.reason or "PASS",
        "passed": bool(result.passed),
        "https": {
            "success": int(result.https_passed),
            "attempted": int(result.https_attempted),
            "total": int(result.https_total),
            "failures": dict(sorted(result.https_diagnostics.items())),
        },
        "r1": _download_record(result.r1),
        "r2": _download_record(result.r2),
        "throughput": {
            "r1_kbps": round(float(result.r1_kbps), 2),
            "r2_kbps": round(float(result.r2_kbps), 2),
            "minimum_kbps": round(float(result.min_kbps), 2),
        },
        "infrastructure_failure": bool(result.is_infrastructure_failure),
    }
