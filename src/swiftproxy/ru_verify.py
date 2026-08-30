from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import os
import sys
import tempfile
import time
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ProxyConfig, RankedConfig, TestResult
from .output import HAPP_PROTOCOLS, happ_subscription, write_json
from .parsing import parse_uri, serialize_uri
from .scoring import diverse_selection
from .testing import sing_box_config, _free_port, _wait_for_core, _stop_process

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
class RuVerifyResult:
    fingerprint: str
    passed: bool
    reason: str | None
    r1_kbps: float = 0.0
    r2_kbps: float = 0.0
    min_kbps: float = 0.0
    https_passed: int = 0
    https_total: int = 3
    services: dict[str, str] = field(default_factory=dict)
    ru_service_ok: bool | None = None
    is_infrastructure_failure: bool = False


async def _curl_probe(
    socks_port: int,
    url: str,
    timeout: float = 4.0,
) -> bool:
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
        return proc.returncode == 0
    except Exception:
        return False


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
        is_stall = proc.returncode == 28 and ("too slow" in stderr.lower() or "speed" in stderr.lower())

        if proc.returncode == 0 and stdout_bytes:
            parts = stdout_bytes.decode().strip().split(":")
            if len(parts) == 4:
                code_str, t_tot_str, size_str, speed_str = parts
                code = int(code_str) if code_str.isdigit() else 0
                time_total = float(t_tot_str) if t_tot_str else elapsed
                size_download = int(size_str) if size_str.isdigit() else 0
                speed_bps = float(speed_str) if speed_str else 0.0
                speed_kbps = speed_bps / 1024.0 if speed_bps > 0 else (size_download / 1024.0) / max(0.001, time_total)
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
                for probe_url in PROBE_URLS:
                    if await _curl_probe(socks_port, probe_url, timeout=4.0):
                        https_passed += 1

                if https_passed < 2:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="HTTPS_FAILED",
                        https_passed=https_passed,
                        https_total=len(PROBE_URLS),
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
                        https_total=len(PROBE_URLS),
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
                        https_total=len(PROBE_URLS),
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
                        https_total=len(PROBE_URLS),
                        r1_kbps=res1.speed_kbps,
                        r2_kbps=res2.speed_kbps,
                        min_kbps=min_speed,
                    )

                # Core test passed. Run service reachability diagnostics.
                services: dict[str, str] = {}
                for svc_name, svc_url in SERVICE_PROBES.items():
                    services[svc_name] = await _probe_service_reachability(socks_port, svc_url, timeout=4.0)

                # RU Egress classification (strictly by resolved geo country == RU)
                is_ru = country == "RU"
                ru_service_ok = None
                if is_ru:
                    ru_service_ok = (
                        services.get("yandex") == "reachable"
                        and (services.get("vk") == "reachable" or services.get("ozon") == "reachable")
                    )

                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=True,
                    reason=None,
                    r1_kbps=res1.speed_kbps,
                    r2_kbps=res2.speed_kbps,
                    min_kbps=min_speed,
                    https_passed=https_passed,
                    https_total=len(PROBE_URLS),
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
    main_file = root / "sub/main.txt"
    white_file = root / "sub/white.txt"

    main_lines = (
        [l.strip() for l in main_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if main_file.exists()
        else []
    )
    white_lines = (
        [l.strip() for l in white_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if white_file.exists()
        else []
    )

    if not main_lines and not white_lines:
        LOGGER.info("sub/main.txt and sub/white.txt are empty or missing; nothing to verify")
        return 0

    history_file = root / "data/history.json"
    history_data = {}
    if history_file.exists():
        try:
            history_data = json.loads(history_file.read_text()).get("configs", {})
        except Exception:
            pass

    # Track membership and parsed configs
    # mapping: fingerprint -> (ProxyConfig, country, is_main, is_white, main_line, white_line)
    unique_candidates: dict[str, tuple[ProxyConfig, str | None, bool, bool, str | None, str | None]] = {}

    for line in main_lines:
        try:
            cfg = parse_uri(line)
            h_cfg = history_data.get(cfg.fingerprint, {})
            obs = (
                h_cfg.get("lanes", {}).get("main", {}).get("observations", [])
                or h_cfg.get("lanes", {}).get("white", {}).get("observations", [])
            )
            country = obs[-1].get("country") if obs else None
            unique_candidates[cfg.fingerprint] = (cfg, country, True, False, line, None)
        except Exception:
            continue

    for line in white_lines:
        try:
            cfg = parse_uri(line)
            h_cfg = history_data.get(cfg.fingerprint, {})
            obs = (
                h_cfg.get("lanes", {}).get("white", {}).get("observations", [])
                or h_cfg.get("lanes", {}).get("main", {}).get("observations", [])
            )
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
        "Starting unified RU sustained-traffic verification for %d candidates (main=%d, white=%d, shared=%d, concurrency=%d, bind_interface=%s)",
        len(unique_candidates),
        len(main_lines),
        len(white_lines),
        sum(1 for c in unique_candidates.values() if c[2] and c[3]),
        concurrency,
        os.environ.get("SWIFT_BIND_INTERFACE", "default"),
    )

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        _verify_single(item[0], sing_box_path, semaphore, item[1])
        for item in unique_candidates.values()
    ]
    results = await asyncio.gather(*tasks)
    results_map: dict[str, RuVerifyResult] = {r.fingerprint: r for r in results}

    # Safe Logging of candidates
    for item in unique_candidates.values():
        cfg, country, is_main, is_white, _, _ = item
        r = results_map.get(cfg.fingerprint)
        if not r:
            continue
        svc_str = " ".join(f"{k[0].upper()}:{v[:2]}" for k, v in r.services.items()) if r.services else "none"
        ru_tag = f" RU_SVC:{'OK' if r.ru_service_ok else 'FAIL'}" if r.ru_service_ok is not None else ""
        lane_tag = "MAIN+WHITE" if (is_main and is_white) else ("MAIN" if is_main else "WHITE")
        LOGGER.info(
            "[%s] %-10s %s | %-10s | R1: %5.1f KB/s | R2: %5.1f KB/s | Min: %5.1f KB/s | HTTPS: %d/%d | Svc: %s%s | %s (%s)",
            cfg.fingerprint[:12],
            cfg.protocol,
            country or "??",
            lane_tag,
            r.r1_kbps,
            r.r2_kbps,
            r.min_kbps,
            r.https_passed,
            r.https_total,
            svc_str,
            ru_tag,
            "PASS" if r.passed else "FAIL",
            r.reason or "OK",
        )

    passed_count = sum(1 for r in results_map.values() if r.passed)
    passed_ratio = passed_count / len(results_map) if results_map else 0.0
    infra_failures = sum(1 for r in results_map.values() if r.is_infrastructure_failure)

    LOGGER.info(
        "RU verification complete: %d/%d passed (%.1f%%, infra_failures=%d)",
        passed_count,
        len(results_map),
        passed_ratio * 100,
        infra_failures,
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
                    lane_rec = history.get("configs", {}).get(cfg.fingerprint, {}).get("lanes", {}).get("main", {})
                    score = float(lane_rec.get("score", 70.0))
                    state = lane_rec.get("state", "active")
                    obs = lane_rec.get("observations", [])
                    prev_succ = next((item for item in reversed(obs) if item.get("success")), {})
                    country = unique_candidates.get(cfg.fingerprint, (None, None))[1] or prev_succ.get("country")
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
        verified_main_lines = [main_line_map[item.config.fingerprint] for item in final_main_ranked if item.config.fingerprint in main_line_map]

        main_file.write_text("\n".join(verified_main_lines) + ("\n" if verified_main_lines else ""))
        happ_main = root / "sub/happ/main.txt"
        if happ_main.exists() or (root / "sub/happ").exists():
            happ_lines = [
                line for line in verified_main_lines
                if parse_uri(line).protocol in HAPP_PROTOCOLS
            ]
            happ_content = happ_subscription(happ_lines, "Swift Main", "https://github.com/femboypig/Swift")
            happ_main.write_text(happ_content)

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
                    lane_rec = history.get("configs", {}).get(cfg.fingerprint, {}).get("lanes", {}).get("white", {})
                    score = float(lane_rec.get("score", 70.0))
                    state = lane_rec.get("state", "active")
                    obs = lane_rec.get("observations", [])
                    prev_succ = next((item for item in reversed(obs) if item.get("success")), {})
                    country = unique_candidates.get(cfg.fingerprint, (None, None))[1] or prev_succ.get("country")
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
        verified_white_lines = [white_line_map[item.config.fingerprint] for item in final_white_ranked if item.config.fingerprint in white_line_map]

        white_file.write_text("\n".join(verified_white_lines) + ("\n" if verified_white_lines else ""))
        happ_white = root / "sub/happ/white.txt"
        if happ_white.exists() or (root / "sub/happ").exists():
            happ_lines = [
                line for line in verified_white_lines
                if parse_uri(line).protocol in HAPP_PROTOCOLS
            ]
            happ_content = happ_subscription(happ_lines, "Swift White", "https://github.com/femboypig/Swift")
            happ_white.write_text(happ_content)

    # 3. Update order.json with final published order
    order["main"] = [item.config.fingerprint for item in final_main_ranked]
    order["white"] = [item.config.fingerprint for item in final_white_ranked]
    if order_file.parent.exists():
        write_json(order_file, order, compact=True)

    # 4. Invariant enforcement
    mac_main_pass_count = sum(
        1 for item in unique_candidates.values()
        if item[2] and results_map.get(item[0].fingerprint) and results_map[item[0].fingerprint].passed
    )
    mac_white_pass_count = sum(
        1 for item in unique_candidates.values()
        if item[3] and results_map.get(item[0].fingerprint) and results_map[item[0].fingerprint].passed
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

    if main_lines:
        disk_main = [l for l in main_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if len(disk_main) != expected_main_count:
            raise RuntimeError(
                f"Invariant violation: sub/main.txt on disk ({len(disk_main)}) != expected ({expected_main_count})"
            )

    if white_lines:
        disk_white = [l for l in white_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if len(disk_white) != expected_white_count:
            raise RuntimeError(
                f"Invariant violation: sub/white.txt on disk ({len(disk_white)}) != expected ({expected_white_count})"
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
                "main": {
                    "before_mac": len(main_lines),
                    "mac_tested": sum(1 for item in unique_candidates.values() if item[2]),
                    "mac_pass": len(verified_main_lines),
                    "mac_fail": len(main_lines) - len(verified_main_lines),
                    "final": final_main_count,
                    "failure_reasons": dict(sorted(mac_fail_reasons.items())),
                },
                "white": {
                    "before_mac": len(white_lines),
                    "mac_tested": sum(1 for item in unique_candidates.values() if item[3]),
                    "mac_pass": len(verified_white_lines),
                    "mac_fail": len(white_lines) - len(verified_white_lines),
                    "final": final_white_count,
                    "failure_reasons": dict(sorted(white_mac_fail_reasons.items())),
                },
            }

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
            write_json(stats_file, stats)
        except Exception:
            pass

    LOGGER.info(
        "Published RU-verified subscriptions: Main=%d (dropped %d), White=%d (dropped %d)",
        len(verified_main_lines),
        len(main_lines) - len(verified_main_lines),
        len(verified_white_lines),
        len(white_lines) - len(verified_white_lines),
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify top Swift candidates through local Russian ISP connection")
    parser.add_argument("--root", default=".")
    parser.add_argument("--core", default=os.environ.get("SWIFT_SING_BOX", ".cache/sing-box/sing-box"))
    parser.add_argument("--concurrency", type=int, default=6)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    root = Path(args.root).resolve()
    core = args.core
    if not Path(core).is_absolute():
        core = str(root / core)

    return asyncio.run(run_ru_verify(root, core, args.concurrency))


if __name__ == "__main__":
    sys.exit(main())
