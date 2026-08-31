from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import os
import shutil
import socket
import sys
import tempfile
import time
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import ProxyConfig, RankedConfig, TestResult
from .output import validated_proxy_lines, write_final_subscriptions, write_json
from .parsing import parse_uri
from .scoring import diverse_selection
from .testing import (
    _direct_socks_address,
    _free_port,
    _stop_process,
    _wait_for_core,
    sing_box_config,
)

LOGGER = logging.getLogger("swift.ru_verify")

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://connectivitycheck.platform.hicloud.com/generate_204",
]
DOWNLOAD_URL_R1 = "https://speed.cloudflare.com/__down?bytes=262144"
DOWNLOAD_URL_R2 = "https://speed.cloudflare.com/__down?bytes=262144"
DOWNLOAD_BYTES = 262144
MIN_THROUGHPUT_KBPS = 64.0
SPEED_LIMIT_BPS = 16384
SPEED_TIME_SECS = 3

SERVICE_PROBES = {
    "yandex": "https://yandex.ru",
    "vk": "https://vk.com",
    "ozon": "https://ozon.ru",
    "telegram_api": "https://api.telegram.org",
}


@dataclass(slots=True)
class DownloadAttempt:
    ok: bool
    status_code: int = 0
    time_total: float = 0.0
    bytes_downloaded: int = 0
    speed_kbps: float = 0.0
    is_stall: bool = False
    error: str | None = None


@dataclass(slots=True)
class HttpsAttempt:
    ok: bool
    diagnostic: str


@dataclass(slots=True)
class MacPreflightResult:
    ok: bool
    interface: str
    dns_ok: bool
    https_passed: int
    https_total: int
    download_ok: bool
    diagnostics: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class RuVerifyResult:
    fingerprint: str
    passed: bool
    reason: str | None = None
    r1_kbps: float = 0.0
    r2_kbps: float = 0.0
    min_kbps: float = 0.0
    https_passed: int = 0
    https_attempted: int = 0
    https_total: int = 3
    https_diagnostics: dict[str, int] = field(default_factory=dict)
    services: dict[str, str] = field(default_factory=dict)
    ru_service_ok: bool | None = None
    is_infrastructure_failure: bool = False


async def _curl_probe(
    socks_port: int,
    url: str,
    timeout: float = 4.0,
) -> HttpsAttempt:
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout",
        str(min(3.0, timeout)),
        "--max-time",
        str(timeout),
        "--output",
        os.devnull,
        url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode == 0:
            return HttpsAttempt(True, "OK")
        return HttpsAttempt(False, f"CURL_{proc.returncode}")
    except Exception:
        return HttpsAttempt(False, "CURL_EXEC_ERROR")


async def _direct_preflight_probe(
    interface: str,
    url: str,
    *,
    timeout: float,
    minimum_bytes: int = 0,
    direct_socks: tuple[str, int] | None = None,
) -> HttpsAttempt:
    cmd = [
        "curl",
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
    if direct_socks:
        host, port = direct_socks
        cmd[4:4] = ["--proxy", f"socks5h://{host}:{port}"]
    else:
        cmd[4:4] = ["--interface", interface]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
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


async def _mac_preflight(interface: str) -> MacPreflightResult:
    diagnostics: Counter[str] = Counter()
    try:
        socket.if_nametoindex(interface)
    except OSError:
        return MacPreflightResult(
            False, interface, False, 0, len(PROBE_URLS), False, {"INTERFACE_MISSING": 1}
        )

    hosts = {urlsplit(url).hostname for url in [*PROBE_URLS, DOWNLOAD_URL_R1]}
    hosts.discard(None)
    loop = asyncio.get_running_loop()
    dns_ok = True
    for host in sorted(hosts):
        try:
            await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError:
            diagnostics["DNS_FAILED"] += 1
            dns_ok = False

    direct_socks = _direct_socks_address()
    https_results = await asyncio.gather(
        *(
            _direct_preflight_probe(
                interface,
                url,
                timeout=8.0,
                direct_socks=direct_socks,
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
        direct_socks=direct_socks,
    )
    if not download.ok:
        diagnostics[download.diagnostic] += 1
    return MacPreflightResult(
        dns_ok and https_passed >= 2 and download.ok,
        interface,
        dns_ok,
        https_passed,
        len(PROBE_URLS),
        download.ok,
        dict(sorted(diagnostics.items())),
    )


def _published_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        1 for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")
    )


def _is_suspicious_collapse(previous: int, current: int) -> bool:
    return previous > 0 and current <= previous * 0.1


async def _curl_download(
    socks_port: int,
    url: str,
    timeout: float = 12.0,
    speed_limit: int = SPEED_LIMIT_BPS,
    speed_time: int = SPEED_TIME_SECS,
) -> DownloadAttempt:
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout",
        "4.0",
        "--max-time",
        str(timeout),
        "--speed-limit",
        str(speed_limit),
        "--speed-time",
        str(speed_time),
        "--write-out",
        "%{http_code}:%{time_total}:%{size_download}:%{speed_download}",
        "--output",
        os.devnull,
        url,
    ]
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        elapsed = time.monotonic() - t0
        stderr = stderr_bytes.decode().strip()
        is_stall = proc.returncode == 28 and (
            "too slow" in stderr.lower() or "speed" in stderr.lower()
        )

        if proc.returncode == 0 and stdout_bytes:
            parts = stdout_bytes.decode().strip().split(":")
            if len(parts) == 4:
                code_str, t_tot_str, size_str, speed_str = parts
                code = int(code_str) if code_str.isdigit() else 0
                time_total = float(t_tot_str) if t_tot_str else elapsed
                size_download = int(size_str) if size_str.isdigit() else 0
                speed_bps = float(speed_str) if speed_str else 0.0
                speed_kbps = (
                    speed_bps / 1024.0
                    if speed_bps > 0
                    else (size_download / 1024.0) / max(0.001, time_total)
                )
                if code in (200, 204, 206) and size_download >= DOWNLOAD_BYTES * 0.9:
                    return DownloadAttempt(
                        ok=True,
                        status_code=code,
                        time_total=time_total,
                        bytes_downloaded=size_download,
                        speed_kbps=speed_kbps,
                    )
        return DownloadAttempt(
            ok=False,
            time_total=elapsed,
            is_stall=is_stall,
            error=stderr or f"EXIT_{proc.returncode}",
        )
    except Exception as exc:
        return DownloadAttempt(
            ok=False,
            time_total=time.monotonic() - t0,
            error=str(exc),
        )


async def _probe_service_reachability(
    socks_port: int,
    url: str,
    timeout: float = 4.0,
) -> str:
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout",
        "3.0",
        "--max-time",
        str(timeout),
        "--write-out",
        "%{http_code}",
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
        stdout_bytes, _ = await proc.communicate()
        if proc.returncode == 0:
            code_str = stdout_bytes.decode().strip()
            if code_str and code_str.isdigit():
                code = int(code_str)
                if code > 0:
                    return "reachable"
        return "unreachable"
    except Exception:
        return "unknown"


async def _verify_single(
    config: ProxyConfig,
    sing_box_path: str,
    semaphore: asyncio.Semaphore,
    country: str | None = None,
) -> RuVerifyResult:
    async with semaphore:
        socks_port = _free_port()
        with tempfile.TemporaryDirectory() as temp_dir:
            cfg_file = Path(temp_dir) / "config.json"
            try:
                sb_cfg = sing_box_config(config, socks_port)
                cfg_file.write_text(json.dumps(sb_cfg))
            except Exception as exc:
                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=False,
                    reason=f"CONFIG_ERROR: {exc}",
                    is_infrastructure_failure=True,
                )

            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    sing_box_path,
                    "run",
                    "-c",
                    str(cfg_file),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception as exc:
                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=False,
                    reason=f"CORE_START_FAILED: {exc}",
                    is_infrastructure_failure=True,
                )

            try:
                ready = await _wait_for_core(process, socks_port)
                if not ready:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="CORE_TIMEOUT",
                        is_infrastructure_failure=True,
                    )

                # 1. HTTPS Reachability (require >= 2 of 3)
                https_passed = 0
                https_attempted = 0
                https_diagnostics: Counter[str] = Counter()
                required_https = 2
                for index, probe_url in enumerate(PROBE_URLS):
                    https_attempted += 1
                    attempt = await _curl_probe(socks_port, probe_url, timeout=4.0)
                    if isinstance(attempt, bool):
                        attempt = HttpsAttempt(attempt, "OK" if attempt else "CURL_UNKNOWN")
                    if attempt.ok:
                        https_passed += 1
                    else:
                        diagnostic = attempt.diagnostic
                        if isinstance(process.returncode, int):
                            diagnostic = "CORE_EXITED"
                        https_diagnostics[diagnostic] += 1

                    remaining = len(PROBE_URLS) - index - 1
                    if https_passed >= required_https:
                        break
                    if https_passed + remaining < required_https:
                        break

                if https_passed < required_https:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="HTTPS_FAILED",
                        https_passed=https_passed,
                        https_attempted=https_attempted,
                        https_total=len(PROBE_URLS),
                        https_diagnostics=dict(sorted(https_diagnostics.items())),
                    )

                # 2. Download Round 1 (256 KB)
                res1 = await _curl_download(socks_port, DOWNLOAD_URL_R1, timeout=12.0)
                if not res1.ok:
                    reason = "STALLED" if res1.is_stall else "DOWNLOAD_R1_FAILED"
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason=reason,
                        https_passed=https_passed,
                        https_attempted=https_attempted,
                        https_total=len(PROBE_URLS),
                        https_diagnostics=dict(sorted(https_diagnostics.items())),
                        r1_kbps=res1.speed_kbps,
                    )

                # 3. Download Round 2 (256 KB)
                res2 = await _curl_download(socks_port, DOWNLOAD_URL_R2, timeout=12.0)
                if not res2.ok:
                    reason = "STALLED" if res2.is_stall else "DOWNLOAD_R2_FAILED"
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason=reason,
                        https_passed=https_passed,
                        https_attempted=https_attempted,
                        https_total=len(PROBE_URLS),
                        https_diagnostics=dict(sorted(https_diagnostics.items())),
                        r1_kbps=res1.speed_kbps,
                        r2_kbps=res2.speed_kbps,
                        min_kbps=min(res1.speed_kbps, res2.speed_kbps),
                    )

                min_speed = min(res1.speed_kbps, res2.speed_kbps)
                if min_speed < MIN_THROUGHPUT_KBPS:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="TOO_SLOW",
                        https_passed=https_passed,
                        https_attempted=https_attempted,
                        https_total=len(PROBE_URLS),
                        https_diagnostics=dict(sorted(https_diagnostics.items())),
                        r1_kbps=res1.speed_kbps,
                        r2_kbps=res2.speed_kbps,
                        min_kbps=min_speed,
                    )

                # Core test passed. Run service reachability diagnostics.
                services: dict[str, str] = {}
                for svc_name, svc_url in SERVICE_PROBES.items():
                    services[svc_name] = await _probe_service_reachability(
                        socks_port, svc_url, timeout=4.0
                    )

                # RU Egress classification (strictly by resolved geo country == RU)
                is_ru = country == "RU"
                ru_service_ok = None
                if is_ru:
                    ru_service_ok = services.get("yandex") == "reachable" and (
                        services.get("vk") == "reachable" or services.get("ozon") == "reachable"
                    )

                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=True,
                    reason=None,
                    r1_kbps=res1.speed_kbps,
                    r2_kbps=res2.speed_kbps,
                    min_kbps=min_speed,
                    https_passed=https_passed,
                    https_attempted=https_attempted,
                    https_total=len(PROBE_URLS),
                    https_diagnostics=dict(sorted(https_diagnostics.items())),
                    services=services,
                    ru_service_ok=ru_service_ok,
                )
            finally:
                if process:
                    await _stop_process(process)


async def run_ru_verify(
    root: Path,
    sing_box_path: str,
    concurrency: int = 6,
) -> int:
    handoff_dir = root / "data/mac-candidates"
    handoff_main = handoff_dir / "main.txt"
    handoff_white = handoff_dir / "white.txt"
    handoff_present = handoff_main.exists() or handoff_white.exists()
    main_input = handoff_main if handoff_present else root / "sub/main.txt"
    white_input = handoff_white if handoff_present else root / "sub/white.txt"
    main_file = root / "sub/main.txt"
    white_file = root / "sub/white.txt"

    main_lines = (
        [
            line.strip()
            for line in main_input.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if main_input.exists()
        else []
    )
    white_lines = (
        [
            line.strip()
            for line in white_input.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if white_input.exists()
        else []
    )
    main_lines = validated_proxy_lines(main_lines, "Mac Main handoff")
    white_lines = validated_proxy_lines(white_lines, "Mac White handoff")

    if not main_lines and not white_lines:
        LOGGER.info("Mac candidate files are empty or missing; nothing to verify")
        return 0

    history_file = root / "data/history.json"
    history_data = {}
    if history_file.exists():
        try:
            history_data = json.loads(history_file.read_text()).get("configs", {})
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("could not read data/history.json for Mac verification") from exc

    # Track membership and parsed configs
    # mapping: fingerprint -> (ProxyConfig, country, is_main, is_white, main_line, white_line)
    unique_candidates: dict[
        str, tuple[ProxyConfig, str | None, bool, bool, str | None, str | None]
    ] = {}

    for line in main_lines:
        try:
            cfg = parse_uri(line)
            h_cfg = history_data.get(cfg.fingerprint, {})
            obs = h_cfg.get("lanes", {}).get("main", {}).get("observations", []) or h_cfg.get(
                "lanes", {}
            ).get("white", {}).get("observations", [])
            country = obs[-1].get("country") if obs else None
            unique_candidates[cfg.fingerprint] = (cfg, country, True, False, line, None)
        except Exception:
            continue

    for line in white_lines:
        try:
            cfg = parse_uri(line)
            h_cfg = history_data.get(cfg.fingerprint, {})
            obs = h_cfg.get("lanes", {}).get("white", {}).get("observations", []) or h_cfg.get(
                "lanes", {}
            ).get("main", {}).get("observations", [])
            country = obs[-1].get("country") if obs else None
            if cfg.fingerprint in unique_candidates:
                existing = unique_candidates[cfg.fingerprint]
                unique_candidates[cfg.fingerprint] = (
                    existing[0],
                    existing[1] or country,
                    existing[2],
                    True,
                    existing[4],
                    line,
                )
            else:
                unique_candidates[cfg.fingerprint] = (cfg, country, False, True, None, line)
        except Exception:
            continue

    LOGGER.info(
        "Starting unified RU sustained-traffic verification for %d candidates (main=%d, white=%d, shared=%d, concurrency=%d, input=%s, bind_interface=%s)",
        len(unique_candidates),
        len(main_lines),
        len(white_lines),
        sum(1 for c in unique_candidates.values() if c[2] and c[3]),
        concurrency,
        "cloud-handoff" if handoff_present else "legacy-sub-files",
        os.environ.get("SWIFT_BIND_INTERFACE", "default"),
    )

    if handoff_present:
        bind_interface = os.environ.get("SWIFT_BIND_INTERFACE")
        if not bind_interface:
            LOGGER.error("RU_PREFLIGHT_FAILED bind_interface is not configured; preserving handoff")
            return 1
        preflight = await _mac_preflight(bind_interface)
        preflight_path = "direct-socks" if _direct_socks_address() else "bound-interface"
        LOGGER.info(
            "RU preflight interface=%s path=%s dns=%s https=%d/%d download=%s diagnostics=%s",
            preflight.interface,
            preflight_path,
            "PASS" if preflight.dns_ok else "FAIL",
            preflight.https_passed,
            preflight.https_total,
            "PASS" if preflight.download_ok else "FAIL",
            preflight.diagnostics or {"OK": 1},
        )
        if not preflight.ok:
            LOGGER.error(
                "RU_PREFLIGHT_FAILED runner/network unhealthy; preserving production and handoff"
            )
            return 1

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(_verify_single(item[0], sing_box_path, semaphore, item[1]))
        for item in unique_candidates.values()
    ]
    results: list[RuVerifyResult] = []
    started = time.monotonic()
    try:
        for completed in asyncio.as_completed(tasks):
            result = await completed
            results.append(result)
            count = len(results)
            if count % 25 == 0 or count == len(tasks):
                elapsed = max(0.001, time.monotonic() - started)
                rate = count / elapsed
                eta_seconds = int((len(tasks) - count) / rate) if rate else 0
                passed = sum(item.passed for item in results)
                reasons = Counter(item.reason or "PASS" for item in results)
                common = ",".join(f"{reason}:{amount}" for reason, amount in reasons.most_common(4))
                LOGGER.info(
                    "RU progress=%d/%d passed=%d failed=%d rate=%.2f/s eta=%ds outcomes=%s",
                    count,
                    len(tasks),
                    passed,
                    count - passed,
                    rate,
                    eta_seconds,
                    common,
                )
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    results_map: dict[str, RuVerifyResult] = {r.fingerprint: r for r in results}

    # Safe Logging of candidates
    for item in unique_candidates.values():
        cfg, country, is_main, is_white, _, _ = item
        r = results_map.get(cfg.fingerprint)
        if not r:
            continue
        svc_str = (
            " ".join(f"{k[0].upper()}:{v[:2]}" for k, v in r.services.items())
            if r.services
            else "none"
        )
        ru_tag = (
            f" RU_SVC:{'OK' if r.ru_service_ok else 'FAIL'}" if r.ru_service_ok is not None else ""
        )
        lane_tag = "MAIN+WHITE" if (is_main and is_white) else ("MAIN" if is_main else "WHITE")
        LOGGER.info(
            "[%s] %-10s %s | %-10s | R1: %5.1f KB/s | R2: %5.1f KB/s | Min: %5.1f KB/s | HTTPS: %d/%d attempted (of %d) | Svc: %s%s | %s (%s)",
            cfg.fingerprint[:12],
            cfg.protocol,
            country or "??",
            lane_tag,
            r.r1_kbps,
            r.r2_kbps,
            r.min_kbps,
            r.https_passed,
            r.https_attempted,
            r.https_total,
            svc_str,
            ru_tag,
            "PASS" if r.passed else "FAIL",
            r.reason or "OK",
        )

    passed_count = sum(1 for r in results_map.values() if r.passed)
    passed_ratio = passed_count / len(results_map) if results_map else 0.0
    infra_failures = sum(1 for r in results_map.values() if r.is_infrastructure_failure)
    https_failure_diagnostics: Counter[str] = Counter()
    for result in results_map.values():
        if result.reason == "HTTPS_FAILED":
            https_failure_diagnostics.update(result.https_diagnostics)

    LOGGER.info(
        "RU verification complete: %d/%d passed (%.1f%%, infra_failures=%d)",
        passed_count,
        len(results_map),
        passed_ratio * 100,
        infra_failures,
    )
    LOGGER.info(
        "RU HTTPS_FAILED diagnostics: %s",
        dict(sorted(https_failure_diagnostics.items())) or {"NONE": 0},
    )

    # Outage / Infrastructure Guard: If verification infrastructure failed, block publishing
    if len(results_map) >= 10 and (infra_failures >= len(results_map) * 0.5):
        LOGGER.error(
            "RU_INFRASTRUCTURE_FAILURE_DETECTED passed=%d/%d infra_failures=%d -> failing verification to prevent publishing broken data",
            passed_count,
            len(results_map),
            infra_failures,
        )
        return 1

    current_main_pass = sum(
        1
        for item in unique_candidates.values()
        if item[2]
        and results_map.get(item[0].fingerprint)
        and results_map[item[0].fingerprint].passed
    )
    current_white_pass = sum(
        1
        for item in unique_candidates.values()
        if item[3]
        and results_map.get(item[0].fingerprint)
        and results_map[item[0].fingerprint].passed
    )
    collapsed_lanes = [
        lane
        for lane, previous, current in (
            ("main", _published_count(main_file), current_main_pass),
            ("white", _published_count(white_file), current_white_pass),
        )
        if _is_suspicious_collapse(previous, current)
    ]
    if handoff_present and collapsed_lanes:
        postflight = await _mac_preflight(os.environ["SWIFT_BIND_INTERFACE"])
        LOGGER.info(
            "RU collapse postflight lanes=%s path=%s dns=%s https=%d/%d download=%s diagnostics=%s",
            ",".join(collapsed_lanes),
            "direct-socks" if _direct_socks_address() else "bound-interface",
            "PASS" if postflight.dns_ok else "FAIL",
            postflight.https_passed,
            postflight.https_total,
            "PASS" if postflight.download_ok else "FAIL",
            postflight.diagnostics or {"OK": 1},
        )
        if not postflight.ok:
            LOGGER.error(
                "RU_INFRASTRUCTURE_COLLAPSE_DETECTED lanes=%s; preserving production and handoff",
                ",".join(collapsed_lanes),
            )
            return 1
        LOGGER.warning(
            "RU proxy population collapsed in %s, but bound-interface postflight is healthy; accepting proxy-level result",
            ",".join(collapsed_lanes),
        )

    # Load config settings for limits and diversity if available
    config_file = root / "config.toml"
    settings: dict[str, Any] = {}
    if config_file.exists():
        try:
            settings = tomllib.loads(config_file.read_text())
        except Exception:
            settings = {}

    main_limit = int(settings.get("limits", {}).get("main", 80))
    white_limit = int(settings.get("limits", {}).get("white", 200))
    diversity = settings.get("diversity", {})
    endpoint_limit = int(diversity.get("endpoint", 3))
    subnet_limit = int(diversity.get("subnet", 6))
    asn_limit = int(diversity.get("asn", 12))

    # Load history and previous published order
    history_file = root / "data/history.json"
    history: dict[str, Any] = {}
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text())
        except Exception:
            history = {}

    order_file = root / "data/order.json"
    order: dict[str, Any] = {}
    if order_file.exists():
        try:
            order = json.loads(order_file.read_text())
        except Exception:
            order = {}

    # 1. Filter, rank, and diverse select Main
    verified_main_lines: list[str] = []
    final_main_ranked: list[RankedConfig] = []
    if main_lines:
        passed_main_ranked: list[RankedConfig] = []
        for line in main_lines:
            try:
                cfg = parse_uri(line)
                r = results_map.get(cfg.fingerprint)
                if r and r.passed:
                    lane_rec = (
                        history.get("configs", {})
                        .get(cfg.fingerprint, {})
                        .get("lanes", {})
                        .get("main", {})
                    )
                    score = float(lane_rec.get("score", 70.0))
                    state = lane_rec.get("state", "active")
                    obs = lane_rec.get("observations", [])
                    prev_succ = next((item for item in reversed(obs) if item.get("success")), {})
                    country = unique_candidates.get(cfg.fingerprint, (None, None))[
                        1
                    ] or prev_succ.get("country")
                    asn = prev_succ.get("asn")
                    provider = prev_succ.get("provider")
                    t_result = TestResult(
                        fingerprint=cfg.fingerprint,
                        lane="main",
                        timestamp="2026-08-31T00:00:00Z",
                        success_count=1,
                        rounds_attempted=1,
                        rounds_succeeded=1,
                        country=country,
                        asn=asn,
                        provider=provider,
                    )
                    passed_main_ranked.append(
                        RankedConfig(
                            config=cfg,
                            lane="main",
                            result=t_result,
                            score=score,
                            state=state,
                            availability=1.0,
                        )
                    )
            except Exception:
                continue

        previous_index_main = {fp: i for i, fp in enumerate(order.get("main", []))}
        passed_main_ranked.sort(
            key=lambda item: (
                -math.floor(item.score),
                previous_index_main.get(item.config.fingerprint, 1_000_000),
                item.config.fingerprint,
            )
        )

        main_line_map = {}
        for line in main_lines:
            try:
                main_line_map[parse_uri(line).fingerprint] = line
            except Exception:
                pass
        final_main_ranked = diverse_selection(
            passed_main_ranked,
            main_limit,
            endpoint_limit,
            subnet_limit,
            asn_limit,
        )
        verified_main_lines = [
            main_line_map[item.config.fingerprint]
            for item in final_main_ranked
            if item.config.fingerprint in main_line_map
        ]

    # 2. Filter, rank, and diverse select White
    verified_white_lines: list[str] = []
    final_white_ranked: list[RankedConfig] = []
    if white_lines:
        passed_white_ranked: list[RankedConfig] = []
        for line in white_lines:
            try:
                cfg = parse_uri(line)
                r = results_map.get(cfg.fingerprint)
                if r and r.passed:
                    lane_rec = (
                        history.get("configs", {})
                        .get(cfg.fingerprint, {})
                        .get("lanes", {})
                        .get("white", {})
                    )
                    score = float(lane_rec.get("score", 70.0))
                    state = lane_rec.get("state", "active")
                    obs = lane_rec.get("observations", [])
                    prev_succ = next((item for item in reversed(obs) if item.get("success")), {})
                    country = unique_candidates.get(cfg.fingerprint, (None, None))[
                        1
                    ] or prev_succ.get("country")
                    asn = prev_succ.get("asn")
                    provider = prev_succ.get("provider")
                    t_result = TestResult(
                        fingerprint=cfg.fingerprint,
                        lane="white",
                        timestamp="2026-08-31T00:00:00Z",
                        success_count=1,
                        rounds_attempted=1,
                        rounds_succeeded=1,
                        country=country,
                        asn=asn,
                        provider=provider,
                    )
                    passed_white_ranked.append(
                        RankedConfig(
                            config=cfg,
                            lane="white",
                            result=t_result,
                            score=score,
                            state=state,
                            availability=1.0,
                        )
                    )
            except Exception:
                continue

        previous_index_white = {fp: i for i, fp in enumerate(order.get("white", []))}
        passed_white_ranked.sort(
            key=lambda item: (
                -math.floor(item.score),
                previous_index_white.get(item.config.fingerprint, 1_000_000),
                item.config.fingerprint,
            )
        )

        white_line_map = {}
        for line in white_lines:
            try:
                white_line_map[parse_uri(line).fingerprint] = line
            except Exception:
                pass
        final_white_ranked = diverse_selection(
            passed_white_ranked,
            white_limit,
            endpoint_limit,
            subnet_limit,
            asn_limit,
        )
        verified_white_lines = [
            white_line_map[item.config.fingerprint]
            for item in final_white_ranked
            if item.config.fingerprint in white_line_map
        ]

    # 3. Prepare order.json with final published order
    order["main"] = [item.config.fingerprint for item in final_main_ranked]
    order["white"] = [item.config.fingerprint for item in final_white_ranked]
    # 4. Invariant enforcement before any production filename is changed
    mac_main_pass_count = sum(
        1
        for item in unique_candidates.values()
        if item[2]
        and results_map.get(item[0].fingerprint)
        and results_map[item[0].fingerprint].passed
    )
    mac_white_pass_count = sum(
        1
        for item in unique_candidates.values()
        if item[3]
        and results_map.get(item[0].fingerprint)
        and results_map[item[0].fingerprint].passed
    )

    expected_main_count = min(mac_main_pass_count, main_limit)
    expected_white_count = min(mac_white_pass_count, white_limit)

    if len(verified_main_lines) != expected_main_count:
        raise RuntimeError(
            f"Invariant violation: verified_main_lines count ({len(verified_main_lines)}) != expected ({expected_main_count})"
        )
    if len(verified_white_lines) != expected_white_count:
        raise RuntimeError(
            f"Invariant violation: verified_white_lines count ({len(verified_white_lines)}) != expected ({expected_white_count})"
        )

    # Stats Update
    stats_file = root / "stats.json"
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
            final_main_count = len(verified_main_lines)
            final_white_count = len(verified_white_lines)

            stats.setdefault("production", {})["main"] = final_main_count
            stats["main"] = final_main_count
            stats.setdefault("production", {})["white"] = final_white_count
            stats["white"] = final_white_count
            stats["published"] = True
            stats["stage"] = "production"

            # Detailed Mac verification stats
            mac_fail_reasons: Counter[str] = Counter()
            white_mac_fail_reasons: Counter[str] = Counter()
            for item in unique_candidates.values():
                cfg, _, is_m, is_w, _, _ = item
                r = results_map.get(cfg.fingerprint)
                if r and not r.passed:
                    reason = r.reason or "UNKNOWN"
                    if is_m:
                        mac_fail_reasons[reason] += 1
                    if is_w:
                        white_mac_fail_reasons[reason] += 1

            stats["mac_verification"] = {
                "https_failure_diagnostics": dict(sorted(https_failure_diagnostics.items())),
                "main": {
                    "before_mac": len(main_lines),
                    "mac_tested": sum(1 for item in unique_candidates.values() if item[2]),
                    "mac_pass": mac_main_pass_count,
                    "mac_fail": len(main_lines) - mac_main_pass_count,
                    "final": final_main_count,
                    "failure_reasons": dict(sorted(mac_fail_reasons.items())),
                },
                "white": {
                    "before_mac": len(white_lines),
                    "mac_tested": sum(1 for item in unique_candidates.values() if item[3]),
                    "mac_pass": mac_white_pass_count,
                    "mac_fail": len(white_lines) - mac_white_pass_count,
                    "final": final_white_count,
                    "failure_reasons": dict(sorted(white_mac_fail_reasons.items())),
                },
            }

            # Load White tcp_tls telemetry from cloud stage
            probe_white_file = root / "data/ru_probe_white.json"
            white_tcp_tls_results: dict[str, str] = {}
            if probe_white_file.exists():
                try:
                    white_tcp_tls_results = json.loads(probe_white_file.read_text())
                except Exception:
                    white_tcp_tls_results = {}

            tcp_tls_matrix = {
                "tcp_tls_pass__mac_pass": 0,
                "tcp_tls_pass__mac_fail": 0,
                "tcp_tls_fail__mac_pass": 0,
                "tcp_tls_fail__mac_fail": 0,
                "tcp_tls_unknown__mac_pass": 0,
                "tcp_tls_unknown__mac_fail": 0,
            }
            for item in unique_candidates.values():
                cfg = item[0]
                is_w = item[3]
                if not is_w:
                    continue
                r = results_map.get(cfg.fingerprint)
                mac_is_pass = bool(r and r.passed)
                tcp_status = white_tcp_tls_results.get(cfg.fingerprint, "unknown")
                if tcp_status == "pass":
                    if mac_is_pass:
                        tcp_tls_matrix["tcp_tls_pass__mac_pass"] += 1
                    else:
                        tcp_tls_matrix["tcp_tls_pass__mac_fail"] += 1
                elif tcp_status == "fail":
                    if mac_is_pass:
                        tcp_tls_matrix["tcp_tls_fail__mac_pass"] += 1
                    else:
                        tcp_tls_matrix["tcp_tls_fail__mac_fail"] += 1
                else:
                    if mac_is_pass:
                        tcp_tls_matrix["tcp_tls_unknown__mac_pass"] += 1
                    else:
                        tcp_tls_matrix["tcp_tls_unknown__mac_fail"] += 1

            white_tcp_tested = sum(
                1
                for item in unique_candidates.values()
                if item[3] and white_tcp_tls_results.get(item[0].fingerprint) in {"pass", "fail"}
            )
            white_tcp_pass = (
                tcp_tls_matrix["tcp_tls_pass__mac_pass"] + tcp_tls_matrix["tcp_tls_pass__mac_fail"]
            )
            white_tcp_fail = (
                tcp_tls_matrix["tcp_tls_fail__mac_pass"] + tcp_tls_matrix["tcp_tls_fail__mac_fail"]
            )
            white_tcp_unknown = (
                tcp_tls_matrix["tcp_tls_unknown__mac_pass"]
                + tcp_tls_matrix["tcp_tls_unknown__mac_fail"]
            )

            telemetry_stats = {
                **tcp_tls_matrix,
                "white_tcp_tls_tested": white_tcp_tested,
                "white_tcp_tls_pass": white_tcp_pass,
                "white_tcp_tls_fail": white_tcp_fail,
                "white_tcp_tls_unknown": white_tcp_unknown,
            }
            stats.setdefault("telemetry", {})["white_tcp_tls_matrix"] = telemetry_stats

            # Full Funnel Telemetry
            main_mac_https_pass = sum(
                1
                for item in unique_candidates.values()
                if item[2]
                and results_map.get(item[0].fingerprint)
                and results_map[item[0].fingerprint].https_passed >= 2
            )
            main_mac_r1_pass = sum(
                1
                for item in unique_candidates.values()
                if item[2]
                and results_map.get(item[0].fingerprint)
                and results_map[item[0].fingerprint].r1_kbps >= 64.0
            )
            main_mac_r2_pass = sum(
                1
                for item in unique_candidates.values()
                if item[2]
                and results_map.get(item[0].fingerprint)
                and results_map[item[0].fingerprint].r2_kbps >= 64.0
            )

            stats.setdefault("funnel", {})
            funnel_main = stats["funnel"].setdefault("main", {})
            funnel_main["main_mac_tested"] = sum(
                1 for item in unique_candidates.values() if item[2]
            )
            funnel_main["main_mac_untested"] = max(
                0,
                funnel_main.get("main_mac_expected", len(main_lines))
                - funnel_main["main_mac_tested"],
            )
            funnel_main["main_mac_https_pass"] = main_mac_https_pass
            funnel_main["main_mac_r1_pass"] = main_mac_r1_pass
            funnel_main["main_mac_r2_pass"] = main_mac_r2_pass
            funnel_main["main_mac_sustained_pass"] = mac_main_pass_count
            funnel_main["main_published"] = final_main_count
            funnel_main["main_mac_completion_pct"] = (
                round((funnel_main["main_mac_tested"] / funnel_main["main_mac_expected"] * 100), 2)
                if funnel_main.get("main_mac_expected")
                else 100.0
            )

            funnel_white = stats["funnel"].setdefault("white", {})
            funnel_white["white_mac_tested"] = sum(
                1 for item in unique_candidates.values() if item[3]
            )
            funnel_white["white_mac_untested"] = max(
                0,
                funnel_white.get("white_mac_expected", len(white_lines))
                - funnel_white["white_mac_tested"],
            )
            funnel_white["white_mac_sustained_pass"] = mac_white_pass_count
            funnel_white["white_published"] = final_white_count
            funnel_white["white_mac_completion_pct"] = (
                round(
                    (funnel_white["white_mac_tested"] / funnel_white["white_mac_expected"] * 100), 2
                )
                if funnel_white.get("white_mac_expected")
                else 100.0
            )
            funnel_white.update(telemetry_stats)

            # Incomplete Run Detection
            is_incomplete = (
                funnel_main.get("main_cloud_untested", 0) > 0
                or funnel_main.get("main_mac_untested", 0) > 0
                or funnel_white.get("white_cloud_untested", 0) > 0
                or funnel_white.get("white_mac_untested", 0) > 0
            )
            if is_incomplete:
                stats["incomplete"] = True
                stats["incomplete_reason"] = "EXHAUSTIVE_VALIDATION_INCOMPLETE"
            else:
                stats["incomplete"] = False

            # Record RU service reachability diagnostics in stats
            ru_diag = {}
            for item in unique_candidates.values():
                cfg = item[0]
                r = results_map.get(cfg.fingerprint)
                if r and r.passed and r.ru_service_ok is not None:
                    ru_diag[cfg.fingerprint[:12]] = {
                        "ru_service_ok": r.ru_service_ok,
                        "services": r.services,
                    }
            stats["ru_service_diagnostics"] = ru_diag
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("could not update stats.json after Mac verification") from exc

    write_final_subscriptions(
        root,
        verified_main_lines,
        verified_white_lines,
        "https://github.com/femboypig/Swift",
    )
    if order_file.parent.exists():
        write_json(order_file, order, compact=True)
    if stats_file.exists():
        write_json(stats_file, stats)

    disk_main = [
        line
        for line in main_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    disk_white = [
        line
        for line in white_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if len(disk_main) != expected_main_count:
        raise RuntimeError(
            f"Invariant violation: sub/main.txt on disk ({len(disk_main)}) != expected ({expected_main_count})"
        )
    if len(disk_white) != expected_white_count:
        raise RuntimeError(
            f"Invariant violation: sub/white.txt on disk ({len(disk_white)}) != expected ({expected_white_count})"
        )

    if handoff_present:
        shutil.rmtree(handoff_dir)

    LOGGER.info(
        "Published RU-verified subscriptions: Main=%d (dropped %d), White=%d (dropped %d)",
        len(verified_main_lines),
        len(main_lines) - len(verified_main_lines),
        len(verified_white_lines),
        len(white_lines) - len(verified_white_lines),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify top Swift candidates through local Russian ISP connection"
    )
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--core", default=os.environ.get("SWIFT_SING_BOX", ".cache/sing-box/sing-box")
    )
    parser.add_argument("--concurrency", type=int, default=6)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    root = Path(args.root).resolve()
    core = args.core
    if not Path(core).is_absolute():
        core = str(root / core)

    return asyncio.run(run_ru_verify(root, core, args.concurrency))


if __name__ == "__main__":
    sys.exit(main())
