from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any
from urllib.parse import urlsplit

from swiftproxy.network import communicate, curl_command
from swiftproxy.verification.constants import DOWNLOAD_BYTES


def _target_id(url: str) -> str:
    host = urlsplit(url).hostname or "unknown"
    return {
        "www.gstatic.com": "gstatic",
        "cp.cloudflare.com": "cloudflare",
        "connectivitycheck.platform.hicloud.com": "hicloud",
    }.get(host, host[:64])


async def _http_probe(port: int, url: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    command = [
        *curl_command(),
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "--connect-timeout",
        str(min(3.0, timeout)),
        "--max-time",
        str(timeout),
        "--max-filesize",
        str(128 * 1024),
        "--output",
        os.devnull,
        "--write-out",
        "%{json}",
        url,
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await communicate(process)
    except OSError:
        return {
            "target": _target_id(url),
            "success": False,
            "status": 0,
            "failure": "CURL_EXEC_ERROR",
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    if process.returncode != 0:
        return {
            "target": _target_id(url),
            "success": False,
            "status": 0,
            "failure": f"CURL_{process.returncode}",
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    try:
        metrics = json.loads(stdout)
        status = int(metrics.get("response_code", 0))
        total = float(metrics.get("time_total", 0)) * 1000
        connect = float(metrics.get("time_connect", 0)) * 1000
        ttfb = float(metrics.get("time_starttransfer", 0)) * 1000
    except (json.JSONDecodeError, TypeError, ValueError):
        return {
            "target": _target_id(url),
            "success": False,
            "status": 0,
            "failure": "CURL_BAD_RESPONSE",
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    success = 200 <= status < 400 and total > 0
    return {
        "target": _target_id(url),
        "success": success,
        "status": status,
        "failure": None if success else f"HTTP_{status}",
        "total_ms": round(total, 2),
        "connect_ms": round(connect, 2),
        "ttfb_ms": round(ttfb, 2),
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def _download(port: int, url: str, limit_bps: int) -> dict[str, Any]:
    command = [
        *curl_command(),
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "--connect-timeout",
        "4",
        "--max-time",
        "12",
        "--speed-limit",
        "16384",
        "--speed-time",
        "3",
        "--limit-rate",
        str(limit_bps),
        "--output",
        os.devnull,
        "--write-out",
        "%{http_code}:%{size_download}:%{speed_download}",
        url,
    ]
    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await communicate(process)
    except OSError:
        return {
            "success": False,
            "category": "CURL_EXEC_ERROR",
            "bytes": 0,
            "speed_kbps": 0.0,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    if process.returncode != 0:
        category = "STALLED" if process.returncode == 28 else f"CURL_{process.returncode}"
        return {
            "success": False,
            "category": category,
            "bytes": 0,
            "speed_kbps": 0.0,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    try:
        status_text, size_text, speed_text = stdout.decode().split(":", 2)
        status, size, speed = int(status_text), int(float(size_text)), float(speed_text) / 1024
    except (UnicodeDecodeError, ValueError):
        return {
            "success": False,
            "category": "CURL_BAD_RESPONSE",
            "bytes": 0,
            "speed_kbps": 0.0,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
    success = status in {200, 204, 206} and size >= DOWNLOAD_BYTES
    return {
        "success": success,
        "status": status,
        "category": None if success else "DOWNLOAD_SHORT",
        "bytes": size,
        "speed_kbps": round(speed, 2),
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def _geo_probe_once(port: int, url: str) -> dict[str, Any]:
    command = [
        *curl_command(),
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "--connect-timeout",
        "3",
        "--max-time",
        "5",
        "--max-filesize",
        str(64 * 1024),
        url,
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await communicate(process)
    except OSError:
        return {}
    if process.returncode != 0 or len(stdout) > 64 * 1024:
        return {}
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        value = {}
        for line in stdout.decode(errors="ignore").splitlines():
            key, separator, item = line.partition("=")
            if separator:
                value[key] = item
    country = value.get("country_code") or value.get("country") or value.get("loc")
    provider = value.get("asOrganization") or value.get("colo")
    try:
        raw_asn = str(value.get("asn", "")).removeprefix("AS")
        asn = int(raw_asn) if raw_asn else None
    except (TypeError, ValueError):
        asn = None
    return {
        "country": str(country).upper()[:2] if country else None,
        "asn": asn,
        "provider": str(provider)[:80] if provider else None,
    }


async def _geo_probe(port: int, url: str) -> dict[str, Any]:
    # Geo enrichment is optional. A second small endpoint avoids turning a
    # transient Cloudflare trace failure into hundreds of unknown labels.
    for candidate in dict.fromkeys((url, "https://speed.cloudflare.com/meta", "https://ipwho.is/")):
        result = await _geo_probe_once(port, candidate)
        if result.get("country"):
            return result
    return {}
