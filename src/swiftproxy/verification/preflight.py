from __future__ import annotations

import asyncio
import os
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from swiftproxy.network import communicate, direct_curl, resolve_direct, validate_interface
from swiftproxy.verification.constants import DOWNLOAD_BYTES, DOWNLOAD_URL_R1, PROBE_URLS


@dataclass(slots=True)
class HttpsAttempt:
    ok: bool
    diagnostic: str


@dataclass(slots=True)
class PathPreflightResult:
    ok: bool
    interface: str
    dns_ok: bool
    https_passed: int
    https_total: int
    download_ok: bool
    diagnostics: dict[str, int] = field(default_factory=dict)


async def _direct_preflight_probe(
    interface: str,
    url: str,
    *,
    timeout: float,
    minimum_bytes: int = 0,
    direct_socks: tuple[str, int] | None = None,
) -> HttpsAttempt:
    if direct_socks:
        return HttpsAttempt(False, "DIRECT_SOCKS_FORBIDDEN")
    try:
        prefix = await direct_curl(url, interface, timeout)
    except (OSError, ValueError):
        return HttpsAttempt(False, "DIRECT_DNS_FAILED")
    cmd = [
        *prefix,
        "--silent",
        "--show-error",
        "--location",
        "--connect-timeout",
        str(min(4.0, timeout)),
        "--max-time",
        str(timeout),
        "--write-out",
        "%{http_code}:%{size_download}",
        "--output",
        os.devnull,
        url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await communicate(proc)
    except Exception:
        return HttpsAttempt(False, "CURL_EXEC_ERROR")
    if proc.returncode != 0:
        return HttpsAttempt(False, f"CURL_{proc.returncode}")
    try:
        status_text, size_text = stdout.decode().strip().split(":", 1)
        status = int(status_text)
        size = int(size_text)
    except (UnicodeDecodeError, ValueError):
        return HttpsAttempt(False, "CURL_BAD_RESPONSE")
    if not 200 <= status < 400:
        return HttpsAttempt(False, f"HTTP_{status}")
    if size < minimum_bytes:
        return HttpsAttempt(False, "DOWNLOAD_SHORT")
    return HttpsAttempt(True, "OK")


async def _physical_preflight(interface: str) -> PathPreflightResult:
    diagnostics: Counter[str] = Counter()
    try:
        validate_interface(interface)
    except (OSError, ValueError, subprocess.SubprocessError):
        return PathPreflightResult(
            False, interface, False, 0, len(PROBE_URLS), False, {"UNSAFE_DIRECT_PATH": 1}
        )

    hosts = {urlsplit(url).hostname for url in [*PROBE_URLS, DOWNLOAD_URL_R1]}
    hosts.discard(None)
    dns_ok = True
    for host in sorted(hosts):
        try:
            await resolve_direct(host, interface)
        except OSError:
            diagnostics["DNS_FAILED"] += 1
            dns_ok = False

    https_results = await asyncio.gather(
        *(
            _direct_preflight_probe(
                interface,
                url,
                timeout=8.0,
            )
            for url in PROBE_URLS
        )
    )
    for result in https_results:
        if not result.ok:
            diagnostics[result.diagnostic] += 1
    https_passed = sum(result.ok for result in https_results)
    download = await _direct_preflight_probe(
        interface,
        DOWNLOAD_URL_R1,
        timeout=12.0,
        minimum_bytes=int(DOWNLOAD_BYTES * 0.9),
    )
    if not download.ok:
        diagnostics[download.diagnostic] += 1
    return PathPreflightResult(
        dns_ok and https_passed >= 2 and download.ok,
        interface,
        dns_ok,
        https_passed,
        len(PROBE_URLS),
        download.ok,
        dict(sorted(diagnostics.items())),
    )
