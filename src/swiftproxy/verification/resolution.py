from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import time
from collections.abc import Callable
from typing import Any

from swiftproxy.models import ProxyConfig
from swiftproxy.network import open_connection, resolve_direct
from swiftproxy.verification.constants import TCP_PROTOCOLS


async def resolve_public_host(
    host: str,
    port: int,
    prefer: Callable[[str], bool] | None = None,
) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            if interface := os.environ.get("SWIFT_BIND_INTERFACE"):
                addresses = await resolve_direct(host, interface)
            else:
                answers = await loop.getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
                addresses = sorted({answer[4][0].split("%", 1)[0] for answer in answers})
        except OSError as exc:
            raise ValueError("DNS_FAILED") from exc
        if not addresses:
            raise ValueError("DNS_FAILED")
        parsed = [ipaddress.ip_address(value) for value in addresses]
        if any(not value.is_global for value in parsed):
            raise ValueError("PRIVATE_ENDPOINT")
        parsed.sort(key=lambda value: (value.version != 4, str(value)))
        if prefer:
            address = next((value for value in parsed if prefer(str(value))), parsed[0])
        else:
            address = parsed[0]
    if not address.is_global:
        raise ValueError("PRIVATE_ENDPOINT")
    return str(address)


def _safe_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


async def resolve_ru(config: ProxyConfig, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        literal = ipaddress.ip_address(config.host)
    except ValueError:
        try:
            loop = asyncio.get_running_loop()
            if interface := os.environ.get("SWIFT_BIND_INTERFACE"):
                values = await asyncio.wait_for(
                    resolve_direct(config.host, interface, timeout), timeout
                )
            else:
                answers = await asyncio.wait_for(
                    loop.getaddrinfo(
                        config.host,
                        config.port,
                        type=socket.SOCK_STREAM,
                        proto=socket.IPPROTO_TCP,
                    ),
                    timeout,
                )
                values = sorted({answer[4][0].split("%", 1)[0] for answer in answers})
        except TimeoutError:
            return {
                "success": False,
                "reason": "DNS_TIMEOUT",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "safe_addresses": [],
                "rejected_answers": [],
            }
        except OSError:
            return {
                "success": False,
                "reason": "DNS_FAILED",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "safe_addresses": [],
                "rejected_answers": [],
            }
    else:
        values = [str(literal)]
    safe = [value for value in values if _safe_address(value)]
    rejected = [
        {"family": f"ipv{ipaddress.ip_address(value).version}", "reason": "UNSAFE_ADDRESS"}
        for value in values
        if not _safe_address(value)
    ]
    if not safe:
        return {
            "success": False,
            "reason": "NO_SAFE_ADDRESS",
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "safe_addresses": [],
            "rejected_answers": rejected,
        }
    safe.sort(key=lambda value: (ipaddress.ip_address(value).version != 4, value))
    selected = safe[0]
    return {
        "success": True,
        "reason": None,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "safe_addresses": safe,
        "rejected_answers": rejected,
        "selected_ip": selected,
        "family": f"ipv{ipaddress.ip_address(selected).version}",
    }


async def endpoint_sanity(config: ProxyConfig, timeout: float) -> dict[str, Any]:
    if config.protocol not in TCP_PROTOCOLS:
        return {
            "applicable": False,
            "attempted": False,
            "success": None,
            "reason": None,
            "duration_ms": 0.0,
        }
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            open_connection(config.resolved_ip or config.host, config.port), timeout
        )
    except (TimeoutError, OSError):
        return {
            "applicable": True,
            "attempted": True,
            "success": False,
            "reason": "ENDPOINT_UNREACHABLE",
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return {
        "applicable": True,
        "attempted": True,
        "success": True,
        "reason": None,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }
