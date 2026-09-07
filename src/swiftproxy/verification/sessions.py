from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from swiftproxy.models import ProxyConfig
from swiftproxy.verification.constants import PROBE_URLS, SERVICE_PROBES
from swiftproxy.verification.core import _start_core, _stop_process
from swiftproxy.verification.limits import StageLimiter
from swiftproxy.verification.probes import _geo_probe, _http_probe


async def _https_session(
    config: ProxyConfig,
    core: str,
    attempts: int,
    required: int,
    timeout: float = 10.0,
    connect_timeout: float | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="swift-ru-") as raw:
        process, port, core_result = await _start_core(config, core, Path(raw))
        if process is None:
            return [], core_result
        records: list[dict[str, Any]] = []
        try:
            offset = int(config.fingerprint[:8], 16) % len(PROBE_URLS)
            targets = [
                PROBE_URLS[(offset + index) % len(PROBE_URLS)] for index in range(len(PROBE_URLS))
            ]
            candidates_to_run = targets[:attempts]
            batch_size = min(required, len(candidates_to_run))
            first_batch = candidates_to_run[:batch_size]
            batch_records = await asyncio.gather(
                *(
                    _http_probe(port, target, timeout=timeout, connect_timeout=connect_timeout)
                    for target in first_batch
                )
            )
            records.extend(batch_records)
            successes: set[str] = {r["target"] for r in records if r["success"]}

            fatal_failures = {"CURL_7", "CURL_97", "CURL_EXEC_ERROR"}
            has_fatal = any(r.get("failure") in fatal_failures for r in records)

            remaining_targets = candidates_to_run[batch_size:]
            for index, target in enumerate(remaining_targets):
                if len(successes) >= required:
                    break
                remaining = len(remaining_targets) - index
                if len(successes) + remaining < required:
                    break
                if has_fatal:
                    break
                record = await _http_probe(
                    port, target, timeout=timeout, connect_timeout=connect_timeout
                )
                records.append(record)
                if record["success"]:
                    successes.add(record["target"])
                if record.get("failure") in fatal_failures:
                    has_fatal = True

            return records, core_result
        finally:
            await _stop_process(process)


async def _service_session(
    config: ProxyConfig,
    core: str,
    stage: StageLimiter,
    geo_url: str | None,
    timeout: float = 10.0,
    connect_timeout: float | None = None,
) -> dict[str, Any]:
    async with stage.slot():
        with tempfile.TemporaryDirectory(prefix="swift-ru-diagnostics-") as raw:
            process, port, core_result = await _start_core(config, core, Path(raw))
            if process is None:
                return {"core": core_result, "results": {}}
            try:
                probe_keys = list(SERVICE_PROBES.keys())
                coros = [
                    _http_probe(
                        port, SERVICE_PROBES[key], timeout=timeout, connect_timeout=connect_timeout
                    )
                    for key in probe_keys
                ]
                if geo_url:
                    coros.append(
                        _geo_probe(port, geo_url, timeout=timeout, connect_timeout=connect_timeout)
                    )
                probe_results = await asyncio.gather(*coros)
                results = {
                    key: res for key, res in zip(probe_keys, probe_results[: len(probe_keys)])
                }
                geo = probe_results[len(probe_keys)] if geo_url else {}
                return {"core": core_result, "results": results, "geo": geo}
            finally:
                await _stop_process(process)


async def _freshness_check(
    config: ProxyConfig,
    core: str,
    timeout: float = 10.0,
    connect_timeout: float | None = None,
) -> dict[str, Any]:
    attempts, core_start = await _https_session(
        config, core, 3, 2, timeout=timeout, connect_timeout=connect_timeout
    )
    successes = {attempt["target"] for attempt in attempts if attempt["success"]}
    return {
        "attempts": attempts,
        "core": core_start,
        "distinct_successes": len(successes),
        "passed": len(successes) >= 2,
    }
