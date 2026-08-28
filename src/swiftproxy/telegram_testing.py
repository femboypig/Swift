from __future__ import annotations

import asyncio
import math
import socket
import struct
from collections import Counter
from typing import Any

from mtproxy_checker.checker import check_once
from mtproxy_checker.errors import MTProxyCheckerError, classify_exception
from mtproxy_checker.models import Mode, ProxyTarget
from mtproxy_checker.parser import decode_secret
from mtproxy_checker.protocol import (
    frame_message,
    make_unencrypted_req_pq_multi,
    parse_res_pq,
)

from .telegram import LOGGER, TelegramProxy, TelegramResult, utc_now
from .testing import resolve_public_host


async def resolve_proxies(
    proxies: list[TelegramProxy], concurrency: int = 100, timeout: float = 8
) -> tuple[list[TelegramProxy], dict[str, str]]:
    semaphore = asyncio.Semaphore(concurrency)
    failures: dict[str, str] = {}

    async def resolve(proxy: TelegramProxy) -> None:
        async with semaphore:
            try:
                proxy.resolved_ip = await asyncio.wait_for(
                    resolve_public_host(proxy.host, proxy.port), timeout
                )
            except TimeoutError:
                failures[proxy.fingerprint] = "DNS_TIMEOUT"
            except ValueError as exc:
                failures[proxy.fingerprint] = str(exc)

    await asyncio.gather(*(resolve(proxy) for proxy in proxies))
    return [proxy for proxy in proxies if proxy.fingerprint not in failures], failures


async def _tcp_prefilter(proxy: TelegramProxy, timeout: float) -> str | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.resolved_ip or proxy.host, proxy.port), timeout
        )
    except TimeoutError:
        return "CONNECT_TIMEOUT"
    except OSError:
        return "CONNECT_FAILED"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return None


async def _telegram_attempt(
    proxy: TelegramProxy, testing: dict[str, Any]
) -> tuple[float | None, str | None]:
    parsed_secret = decode_secret(proxy.secret)
    target = ProxyTarget(proxy.resolved_ip or proxy.host, proxy.port, parsed_secret)
    mode = Mode.FAKETLS if parsed_secret.is_faketls else Mode.SECURE
    connect_timeout = float(testing["connect_timeout"])
    response_timeout = float(testing["response_timeout"])
    try:
        rtt, _ = await asyncio.wait_for(
            asyncio.to_thread(
                check_once,
                target,
                2,
                connect_timeout,
                response_timeout,
                mode,
            ),
            connect_timeout + response_timeout + 2,
        )
    except TimeoutError:
        return None, "RESPONSE_TIMEOUT"
    except (MTProxyCheckerError, OSError) as exc:
        code, _, _ = classify_exception(exc)
        return None, code.value
    return round(rtt, 2), None


async def test_proxies(
    proxies: list[TelegramProxy], testing: dict[str, Any]
) -> list[TelegramResult]:
    semaphore = asyncio.Semaphore(int(testing["concurrency"]))
    configured_attempts = int(testing["attempts"])

    async def test(proxy: TelegramProxy) -> TelegramResult:
        async with semaphore:
            timestamp = utc_now()
            tcp_reason = await _tcp_prefilter(proxy, float(testing["connect_timeout"]))
            if tcp_reason:
                return TelegramResult(proxy.fingerprint, timestamp, reason=tcp_reason)
            rtts: list[float] = []
            reasons: Counter[str] = Counter()
            for _ in range(configured_attempts):
                rtt, reason = await _telegram_attempt(proxy, testing)
                if rtt is not None:
                    rtts.append(rtt)
                elif reason:
                    reasons[reason] += 1
            successes = len(rtts)
            reason = None
            if successes < math.ceil(configured_attempts * 2 / 3):
                reason = reasons.most_common(1)[0][0] if reasons else "PROTOCOL_ERROR"
            elif successes < configured_attempts:
                reason = "UNSTABLE"
            result = TelegramResult(
                proxy.fingerprint,
                timestamp,
                attempts=configured_attempts,
                successes=successes,
                rtts_ms=rtts,
                reason=reason,
            )
            LOGGER.info(
                "mtproto result=%s attempts=%d successes=%d median_ms=%s reason=%s",
                proxy.fingerprint[:12],
                result.attempts,
                result.successes,
                round(result.median_rtt, 1) if result.median_rtt is not None else None,
                result.reason or "OK",
            )
            return result

    tasks = [asyncio.create_task(test(proxy)) for proxy in proxies]
    done, pending = await asyncio.wait(tasks, timeout=float(testing["global_timeout"]))
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
        LOGGER.warning("GLOBAL_TIMEOUT unfinished=%d", len(pending))
    return [task.result() for task in done if not task.cancelled() and task.exception() is None]


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise OSError("connection closed")
        output.extend(chunk)
    return bytes(output)


def _direct_telegram_check(endpoint: str, timeout: float) -> bool:
    host, separator, port_value = endpoint.rpartition(":")
    if not separator:
        return False
    nonce, message = make_unencrypted_req_pq_multi()
    with socket.create_connection((host, int(port_value)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\xef" + frame_message(message, Mode.ABRIDGED))
        first = _recv_exact(sock, 1)[0]
        if first < 127:
            length = first * 4
        else:
            length = struct.unpack("<I", _recv_exact(sock, 3) + b"\0")[0] * 4
        if not 0 < length <= 2 * 1024 * 1024:
            return False
        parse_res_pq(_recv_exact(sock, length), nonce)
    return True


async def telegram_control(testing: dict[str, Any]) -> bool:
    timeout = float(testing["control_timeout"])
    endpoints = list(testing["control_endpoints"])
    tasks = [asyncio.to_thread(_direct_telegram_check, endpoint, timeout) for endpoint in endpoints]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    passed = sum(result is True for result in results)
    LOGGER.info("telegram control passed=%d checked=%d", passed, len(endpoints))
    return passed > 0
