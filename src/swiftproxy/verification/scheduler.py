from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

from swiftproxy.protocols.parser import parse_uri
from swiftproxy.verification.candidate import CandidateVerifier
from swiftproxy.verification.health import _wait_for_healthy_path
from swiftproxy.verification.results import _apply_freshness
from swiftproxy.verification.sessions import _freshness_check

LOGGER = logging.getLogger(__name__)


@dataclass
class ScheduleResult:
    results: list[dict[str, Any]]
    complete: bool
    failure: str | None
    running_checks: list[dict[str, Any]]
    freshness_checks: list[dict[str, Any]]
    freshness_candidates: list[dict[str, Any]]


async def run_candidates(
    candidates: list[dict[str, Any]], verifier: CandidateVerifier
) -> ScheduleResult:
    deadline_at = time.monotonic() + float(verifier.ru["run_deadline_seconds"])
    tasks: list[asyncio.Task[dict[str, Any]]] = []
    results: list[dict[str, Any]] = []
    complete = True
    run_failure: str | None = None
    running_path_checks: list[dict[str, Any]] = []
    freshness_path_checks: list[dict[str, Any]] = []
    run_started = time.monotonic()
    last_progress = run_started
    LOGGER.info(
        "RU generation=%s expected=%d path_mode=%s",
        verifier.manifest["generation_id"][:12],
        len(candidates),
        verifier.control["path_mode"],
    )
    try:
        async with asyncio.timeout(max(0.0, deadline_at - time.monotonic())):
            for offset in range(0, len(candidates), int(verifier.ru["path_check_interval"])):
                if offset:
                    health, checks = await _wait_for_healthy_path(
                        verifier.interface,
                        verifier.core,
                        float(verifier.ru["preflight_timeout"]),
                        int(verifier.ru["path_recovery_attempts"]),
                        float(verifier.ru["path_recovery_delay_seconds"]),
                        int(verifier.ru["path_recovery_confirmations"]),
                        f"running-{offset}",
                    )
                    running_path_checks.extend(checks)
                    if not health.healthy:
                        complete = False
                        run_failure = "RU_PATH_UNHEALTHY"
                        break
                batch = candidates[offset : offset + int(verifier.ru["path_check_interval"])]
                tasks = [asyncio.create_task(verifier.bounded(item)) for item in batch]
                for task in asyncio.as_completed(tasks):
                    results.append(await task)
                    now_mono = time.monotonic()
                    if len(results) % 25 == 0 or now_mono - last_progress >= 30:
                        elapsed = max(0.001, now_mono - run_started)
                        rate = len(results) / elapsed
                        remaining = len(candidates) - len(results)
                        LOGGER.info(
                            "RU progress=%d/%d rate=%.2f/s eta=%.0fs",
                            len(results),
                            len(candidates),
                            rate,
                            remaining / rate if rate else 0,
                        )
                        last_progress = now_mono
                tasks = []
    except TimeoutError:
        complete = False
        run_failure = "RUN_DEADLINE"
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except BaseException as exc:
        complete = False
        run_failure = type(exc).__name__.upper()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    retry_by_fp = {result["fingerprint"] for result in results if result.get("retry_recommended")}
    if complete and retry_by_fp:
        await asyncio.sleep(float(verifier.ru["retry_delay_seconds"]))
        retry_items = [item for item in candidates if item["fingerprint"] in retry_by_fp]
        retry_tasks = [
            asyncio.create_task(verifier.bounded(item, retry=True)) for item in retry_items
        ]
        try:
            async with asyncio.timeout(max(0.0, deadline_at - time.monotonic())):
                retry_results = await asyncio.gather(*retry_tasks)
        except TimeoutError:
            complete = False
            run_failure = "RUN_DEADLINE"
            for task in retry_tasks:
                task.cancel()
            await asyncio.gather(*retry_tasks, return_exceptions=True)
        else:
            retry_map = {result["fingerprint"]: result for result in retry_results}
            results = [retry_map.get(result["fingerprint"], result) for result in results]
    candidate_by_fingerprint = {item["fingerprint"]: item for item in candidates}
    freshness_candidates = [result for result in results if result["final"]["passed"]]
    if complete and freshness_candidates:
        health, checks = await _wait_for_healthy_path(
            verifier.interface,
            verifier.core,
            float(verifier.ru["preflight_timeout"]),
            int(verifier.ru["path_recovery_attempts"]),
            float(verifier.ru["path_recovery_delay_seconds"]),
            int(verifier.ru["path_recovery_confirmations"]),
            "freshness",
        )
        freshness_path_checks.extend(checks)
        if not health.healthy:
            complete = False
            run_failure = "RU_PATH_UNHEALTHY"
        else:

            async def revalidate(result: dict[str, Any]) -> None:
                item = candidate_by_fingerprint[result["fingerprint"]]
                config = parse_uri(item["uri"])
                config.resolved_ip = result["resolution"]["selected_ip"]
                async with verifier.stability_stage.slot():
                    freshness = await _freshness_check(
                        config,
                        verifier.core,
                        timeout=float(verifier.ru.get("https_timeout", 10.0)),
                        connect_timeout=float(verifier.ru.get("https_connect_timeout", 7.0)),
                    )
                _apply_freshness(result, freshness)

            freshness_tasks = [
                asyncio.create_task(revalidate(result)) for result in freshness_candidates
            ]
            try:
                async with asyncio.timeout(max(0.0, deadline_at - time.monotonic())):
                    await asyncio.gather(*freshness_tasks)
            except TimeoutError:
                complete = False
                run_failure = "RUN_DEADLINE"
                for task in freshness_tasks:
                    task.cancel()
                await asyncio.gather(*freshness_tasks, return_exceptions=True)
            except BaseException as exc:
                complete = False
                run_failure = type(exc).__name__.upper()
                for task in freshness_tasks:
                    task.cancel()
                await asyncio.gather(*freshness_tasks, return_exceptions=True)
    return ScheduleResult(
        results,
        complete,
        run_failure,
        running_path_checks,
        freshness_path_checks,
        freshness_candidates,
    )
