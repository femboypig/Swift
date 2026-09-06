from __future__ import annotations

import asyncio
from typing import Any

from swiftproxy.mtproto.models import TelegramProxy, TelegramResult, utc_now
from swiftproxy.ru_probe import probe_ru_targets


async def _probe_round(
    candidates: list[TelegramProxy], testing: dict[str, Any]
) -> tuple[dict[str, TelegramResult], bool]:
    targets = [
        {
            "id": proxy.fingerprint,
            "host": proxy.host,
            "port": proxy.port,
            "secret": proxy.secret,
        }
        for proxy in candidates
    ]
    probe_results = await asyncio.to_thread(
        probe_ru_targets,
        targets,
        "mtproto",
        chunk_size=int(testing["probe_chunk_size"]),
        request_concurrency=int(testing["probe_concurrency"]),
    )
    timestamp = utc_now()
    results: dict[str, TelegramResult] = {}
    for proxy in candidates:
        item = probe_results.get(proxy.fingerprint)
        if item is None:
            continue
        latency = item.get("latency_ms")
        ok = bool(item.get("ok"))
        results[proxy.fingerprint] = TelegramResult(
            proxy.fingerprint,
            timestamp,
            attempts=1,
            successes=1 if ok else 0,
            rtts_ms=[float(latency)] if ok and latency is not None else [],
            reason=None if ok else str(item.get("error") or "PROTOCOL_ERROR")[:64],
        )
    return results, len(results) == len(candidates)


async def _test_with_ru_probe(
    candidates: list[TelegramProxy], testing: dict[str, Any]
) -> tuple[dict[str, TelegramResult], bool]:
    attempts = int(testing["probe_attempts"])
    if attempts < 3:
        raise ValueError("Telegram verification requires at least three attempts")
    results = {
        proxy.fingerprint: TelegramResult(proxy.fingerprint, utc_now()) for proxy in candidates
    }
    missing: set[str] = set()
    complete = True
    for _ in range(attempts):
        repeated, round_complete = await _probe_round(candidates, testing)
        complete = complete and round_complete
        for proxy in candidates:
            extra = repeated.get(proxy.fingerprint)
            if extra is None:
                missing.add(proxy.fingerprint)
                continue
            result = results[proxy.fingerprint]
            result.attempts += extra.attempts
            result.successes += extra.successes
            result.rtts_ms.extend(extra.rtts_ms)
            if extra.reason:
                result.reason = extra.reason
    for fingerprint in missing:
        del results[fingerprint]
    for result in results.values():
        if result.successes == result.attempts:
            result.reason = None
        elif result.working:
            result.reason = "UNSTABLE"
    return results, complete
