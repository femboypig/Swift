from __future__ import annotations

import asyncio
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from swiftproxy.protocols.parser import parse_uri
from swiftproxy.protocols.security import validate_security
from swiftproxy.verification.constants import (
    DOWNLOAD_URL_R1,
    DOWNLOAD_URL_R2,
    MIN_THROUGHPUT_KBPS,
    RESULT_SCHEMA_VERSION,
    TERMINAL_PASS,
)
from swiftproxy.verification.core import _start_core, _stop_process
from swiftproxy.verification.limits import DownloadGovernor, StageLimiter, _run_admitted
from swiftproxy.verification.probes import _download
from swiftproxy.verification.resolution import endpoint_sanity, resolve_ru
from swiftproxy.verification.results import _percentile, _terminal, download_failure_reason
from swiftproxy.verification.sessions import _https_session, _service_session
from swiftproxy.whitelist import _white_signal


class CandidateVerifier:
    def __init__(self, core, manifest, settings, history, evidence, control, interface):
        self.core = core
        self.manifest = manifest
        self.settings = settings
        self.history = history
        self.evidence = evidence
        self.control = control
        self.interface = interface
        self.ru = settings["ru"]
        self.resolution_stage = StageLimiter(int(self.ru["resolution_concurrency"]))
        self.endpoint_stage = StageLimiter(int(self.ru["endpoint_concurrency"]))
        self.initial_stage = StageLimiter(int(self.ru["https_concurrency"]))
        self.stability_stage = StageLimiter(int(self.ru["stability_concurrency"]))
        self.diagnostic_stage = StageLimiter(int(self.ru["diagnostic_concurrency"]))
        self.candidate_admission = asyncio.Semaphore(
            sum(
                int(self.ru[key])
                for key in (
                    "resolution_concurrency",
                    "endpoint_concurrency",
                    "https_concurrency",
                    "stability_concurrency",
                    "download_concurrency",
                    "diagnostic_concurrency",
                )
            )
        )
        self.governor = DownloadGovernor(
            int(self.ru["download_concurrency"]),
            int(self.ru["download_bandwidth_bps"]),
            interface,
            float(control["latency_ms"]),
        )

    async def verify(self, item: dict[str, Any], retry: bool = False) -> dict[str, Any]:
        config = parse_uri(item["uri"])
        validate_security(config)
        if config.fingerprint != item["fingerprint"]:
            raise ValueError("candidate fingerprint does not match its serialized config")
        record: dict[str, Any] = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "generation_id": self.manifest["generation_id"],
            "fingerprint": item["fingerprint"],
            "protocol": config.protocol,
            "sources": item["sources"],
            "candidate_sources": item["candidate_sources"],
            "lanes": item["lanes"],
            "retry": retry,
            "_started": time.monotonic(),
            "infrastructure": {
                "path_mode": self.control["path_mode"],
                "preflight": "PASS",
                "congestion": False,
            },
        }
        async with self.resolution_stage.slot():
            resolution = await resolve_ru(config, float(self.ru["resolution_timeout"]))
        record["resolution"] = resolution
        if not resolution["success"]:
            return _terminal(record, resolution["reason"])
        config.resolved_ip = resolution["selected_ip"]
        record["white"] = {
            "upstream_label": bool(item["upstream_white_label"]),
            "evidence": _white_signal(config, config.resolved_ip, self.evidence),
        }
        async with self.endpoint_stage.slot():
            endpoint = await endpoint_sanity(config, float(self.ru["endpoint_timeout"]))
        record["endpoint"] = endpoint
        https_timeout = float(self.ru.get("https_timeout", 10.0))
        https_connect_timeout = float(self.ru.get("https_connect_timeout", 7.0))
        download_timeout = float(self.ru.get("download_timeout", 20.0))
        download_connect_timeout = float(self.ru.get("download_connect_timeout", 7.0))
        download_speed_time = int(self.ru.get("download_speed_time", 8))

        async with self.initial_stage.slot():
            initial, core_start = await _https_session(
                config,
                self.core,
                3,
                2,
                https_timeout,
                https_connect_timeout,
            )
        record["core"] = {"initial": core_start}
        record["https"] = {"initial": initial}
        distinct = {attempt["target"] for attempt in initial if attempt["success"]}
        if len(distinct) < 2:
            record["retry_recommended"] = bool(distinct) or bool(
                self.history.get("configs", {}).get(config.fingerprint, {}).get("last_pass")
            )
            reason = core_start.get("category") or "HTTPS_FAILED"
            return _terminal(record, reason)
        async with self.stability_stage.slot():
            stability, stability_core = await _https_session(
                config,
                self.core,
                3,
                2,
                https_timeout,
                https_connect_timeout,
            )
        record["core"]["stability"] = stability_core
        record["https"]["stability"] = stability
        stability_distinct = {attempt["target"] for attempt in stability if attempt["success"]}
        if len(stability_distinct) < 2:
            record["retry_recommended"] = True
            return _terminal(record, stability_core.get("category") or "UNSTABLE")
        latencies = [
            attempt["total_ms"] for attempt in [*initial, *stability] if attempt["success"]
        ]
        record["latency"] = {
            "median_ms": round(statistics.median(latencies), 2),
            "p95_ms": _percentile(latencies, 0.95),
            "jitter_ms": round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0,
        }
        congestion = await self.governor.control(
            float(self.ru["congestion_latency_factor"]),
            float(self.ru["congestion_latency_floor_ms"]),
        )
        record["infrastructure"]["download_control"] = congestion
        if congestion["congested"]:
            record["infrastructure"]["congestion"] = True
            record["retry_recommended"] = True
            return _terminal(record, "DEFER_LOCAL_CONGESTION")
        async with self.governor.slot():
            with tempfile.TemporaryDirectory(prefix="swift-ru-download-") as raw:
                process, port, download_core = await _start_core(config, self.core, Path(raw))
                record["core"]["download"] = download_core
                if process is None:
                    return _terminal(record, download_core.get("category") or "CORE_START_FAILED")
                try:
                    r1 = await _download(
                        port,
                        DOWNLOAD_URL_R1,
                        self.governor.per_transfer_bps,
                        download_timeout,
                        download_connect_timeout,
                        download_speed_time,
                    )
                    self.governor.bytes += int(r1.get("bytes", 0))
                    record["r1"] = r1
                    r1_reason = download_failure_reason(r1, "R1", check_speed=False)
                    if r1_reason:
                        control_after = await self.governor.control(
                            float(self.ru["congestion_latency_factor"]),
                            float(self.ru["congestion_latency_floor_ms"]),
                        )
                        record["infrastructure"]["download_control_after"] = control_after
                        if control_after["congested"]:
                            record["retry_recommended"] = True
                            return _terminal(record, "DEFER_LOCAL_CONGESTION")
                        return _terminal(record, r1_reason)
                    r2 = await _download(
                        port,
                        DOWNLOAD_URL_R2,
                        self.governor.per_transfer_bps,
                        download_timeout,
                        download_connect_timeout,
                        download_speed_time,
                    )
                    self.governor.bytes += int(r2.get("bytes", 0))
                    record["r2"] = r2
                finally:
                    await _stop_process(process)
        r2_reason = download_failure_reason(record["r2"], "R2", check_speed=False)
        if r2_reason:
            control_after = await self.governor.control(
                float(self.ru["congestion_latency_factor"]),
                float(self.ru["congestion_latency_floor_ms"]),
            )
            record["infrastructure"]["download_control_after"] = control_after
            if control_after["congested"]:
                record["retry_recommended"] = True
                return _terminal(record, "DEFER_LOCAL_CONGESTION")
            return _terminal(record, r2_reason)
        if min(record["r1"]["speed_kbps"], record["r2"]["speed_kbps"]) < MIN_THROUGHPUT_KBPS:
            control_after = await self.governor.control(
                float(self.ru["congestion_latency_factor"]),
                float(self.ru["congestion_latency_floor_ms"]),
            )
            record["infrastructure"]["download_control_after"] = control_after
            if control_after["congested"]:
                record["retry_recommended"] = True
                return _terminal(record, "DEFER_LOCAL_CONGESTION")
            return _terminal(record, "TOO_SLOW")
        try:
            record["services"] = await asyncio.wait_for(
                _service_session(
                    config,
                    self.core,
                    self.diagnostic_stage,
                    str(self.settings["testing"].get("geo_url") or ""),
                    https_timeout,
                    https_connect_timeout,
                ),
                max(15.0, https_timeout + 5.0),
            )
        except TimeoutError:
            record["services"] = {"category": "DIAGNOSTIC_TIMEOUT", "results": {}}
        return _terminal(record, TERMINAL_PASS, True)

    async def bounded(self, item: dict[str, Any], retry: bool = False) -> dict[str, Any]:
        try:
            return await _run_admitted(
                self.candidate_admission,
                lambda: self.verify(item, retry=retry),
                float(self.ru["per_config_timeout"]),
            )
        except ValueError:
            return {
                "schema_version": RESULT_SCHEMA_VERSION,
                "generation_id": self.manifest["generation_id"],
                "fingerprint": item.get("fingerprint", "INVALID"),
                "protocol": item.get("protocol", "unknown"),
                "sources": item.get("sources", []),
                "candidate_sources": item.get("candidate_sources", []),
                "lanes": item.get("lanes", []),
                "final": {
                    "terminal_state": "FAIL",
                    "reason": "CONFIG_REJECTED",
                    "passed": False,
                    "accounted_for": True,
                },
            }
        except TimeoutError:
            return {
                "schema_version": RESULT_SCHEMA_VERSION,
                "generation_id": self.manifest["generation_id"],
                "fingerprint": item["fingerprint"],
                "protocol": item["protocol"],
                "sources": item["sources"],
                "candidate_sources": item["candidate_sources"],
                "lanes": item["lanes"],
                "final": {
                    "terminal_state": "FAIL",
                    "reason": "CONFIG_TIMEOUT",
                    "passed": False,
                    "accounted_for": True,
                },
            }
