from __future__ import annotations

import asyncio
import math
import os
import socket
import struct
import time
from collections import Counter
from typing import Any

from mtproxy_checker.attempts import effective_inner_mode
from mtproxy_checker.errors import MTProxyCheckerError, classify_exception
from mtproxy_checker.models import Mode
from mtproxy_checker.parser import decode_secret
from mtproxy_checker.protocol import (
    frame_message,
    make_obfuscated2_handshake,
    make_unencrypted_req_pq_multi,
    parse_res_pq,
    read_frame,
)
from mtproxy_checker.transports import FakeTlsTransport, PlainTransport

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


def _direct_socks() -> tuple[str, int] | None:
    value = os.environ.get("SWIFT_DIRECT_SOCKS", "").strip()
    if not value:
        return None
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError("SWIFT_DIRECT_SOCKS must be host:port")
    try:
        port_number = int(port)
    except ValueError as exc:
        raise ValueError("SWIFT_DIRECT_SOCKS port must be an integer") from exc
    if not 1 <= port_number <= 65535:
        raise ValueError("SWIFT_DIRECT_SOCKS port is out of range")
    try:
        if not socket.inet_pton(socket.AF_INET, host) == b"\x7f\x00\x00\x01":
            raise ValueError("SWIFT_DIRECT_SOCKS must point to loopback")
    except OSError:
        if host != "localhost":
            raise ValueError("SWIFT_DIRECT_SOCKS must point to loopback") from None
    return host, port_number


def _connect(proxy: TelegramProxy, timeout: float) -> socket.socket:
    endpoint = proxy.resolved_ip or proxy.host
    direct = _direct_socks()
    if direct is None:
        return socket.create_connection((endpoint, proxy.port), timeout=timeout)
    sock = socket.create_connection(direct, timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication negotiation failed")
        try:
            packed = socket.inet_pton(socket.AF_INET, endpoint)
            address = b"\x01" + packed
        except OSError:
            try:
                packed = socket.inet_pton(socket.AF_INET6, endpoint)
                address = b"\x04" + packed
            except OSError:
                encoded = endpoint.encode("idna")
                if len(encoded) > 255:
                    raise OSError("SOCKS destination is too long") from None
                address = b"\x03" + bytes([len(encoded)]) + encoded
        sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", proxy.port))
        head = _recv_exact(sock, 4)
        if head[:2] != b"\x05\x00":
            raise OSError("SOCKS connect failed")
        if head[3] == 1:
            _recv_exact(sock, 4)
        elif head[3] == 4:
            _recv_exact(sock, 16)
        elif head[3] == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        else:
            raise OSError("SOCKS returned an invalid address type")
        _recv_exact(sock, 2)
        return sock
    except BaseException:
        sock.close()
        raise


async def _tcp_prefilter(proxy: TelegramProxy, timeout: float) -> str | None:
    try:
        sock = await asyncio.wait_for(asyncio.to_thread(_connect, proxy, timeout), timeout + 1)
    except TimeoutError:
        return "CONNECT_TIMEOUT"
    except OSError:
        return "CONNECT_FAILED"
    sock.close()
    return None


def _check_once(
    proxy: TelegramProxy, mode: Mode, connect_timeout: float, response_timeout: float
) -> float:
    begin = time.monotonic()
    parsed_secret = decode_secret(proxy.secret)
    sock = _connect(proxy, connect_timeout)
    with sock:
        sock.settimeout(response_timeout)
        transport: FakeTlsTransport | PlainTransport
        if mode == Mode.FAKETLS:
            transport = FakeTlsTransport(
                sock, parsed_secret.raw_secret, parsed_secret.faketls_domain
            )
            transport.handshake()
        else:
            transport = PlainTransport(sock)
        inner_mode = effective_inner_mode(mode)
        init_packet, enc, dec = make_obfuscated2_handshake(parsed_secret.raw_secret, inner_mode, 2)
        transport.write(init_packet)
        nonce, request = make_unencrypted_req_pq_multi()
        transport.write(enc.update(frame_message(request, inner_mode)))
        parse_res_pq(read_frame(transport, dec, inner_mode), nonce)
    return (time.monotonic() - begin) * 1000


async def _telegram_attempt(
    proxy: TelegramProxy, testing: dict[str, Any]
) -> tuple[float | None, str | None]:
    parsed_secret = decode_secret(proxy.secret)
    mode = Mode.FAKETLS if parsed_secret.is_faketls else Mode.SECURE
    connect_timeout = float(testing["connect_timeout"])
    response_timeout = float(testing["response_timeout"])
    try:
        rtt = await asyncio.wait_for(
            asyncio.to_thread(
                _check_once,
                proxy,
                mode,
                connect_timeout,
                response_timeout,
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
    proxy = TelegramProxy(host, int(port_value), "11" * 16, "raw", resolved_ip=host)
    with _connect(proxy, timeout) as sock:
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
