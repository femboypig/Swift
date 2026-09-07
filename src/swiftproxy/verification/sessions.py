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
            successes: set[str] = set()
            for index, target in enumerate(targets[:attempts]):
                record = await _http_probe(
                    port, target, timeout=timeout, connect_timeout=connect_timeout
                )
                records.append(record)
                if record["success"]:
                    successes.add(record["target"])
                remaining = attempts - index - 1
                if len(successes) >= required:
                    break
                if len(successes) + remaining < required:
                    break
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
                results = {
                    name: await _http_probe(
                        port, url, timeout=timeout, connect_timeout=connect_timeout
                    )
                    for name, url in SERVICE_PROBES.items()
                }
                geo = (
                    await _geo_probe(
                        port, geo_url, timeout=timeout, connect_timeout=connect_timeout
                    )
                    if geo_url
                    else {}
                )
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
