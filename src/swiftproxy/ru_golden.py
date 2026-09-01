from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import math
import os
import socket
import statistics
import tempfile
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .generation import read_jsonl
from .models import ProxyConfig, RankedConfig, TestResult
from .output import subscription_lines, write_final_subscriptions, write_json
from .parsing import parse_uri
from .ru_verify import (
    DOWNLOAD_BYTES,
    DOWNLOAD_URL_R1,
    DOWNLOAD_URL_R2,
    MIN_THROUGHPUT_KBPS,
    PROBE_URLS,
    SERVICE_PROBES,
    _mac_preflight,
)
from .scoring import diverse_selection
from .telemetry import write_jsonl
from .testing import (
    _direct_socks_address,
    _free_port,
    _stop_process,
    _wait_for_core,
    sing_box_config,
)


RESULT_SCHEMA_VERSION = 1
TCP_PROTOCOLS = {"vless", "vmess", "trojan", "ss"}
TERMINAL_PASS = "PASS"


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _target_id(url: str) -> str:
    host = urlsplit(url).hostname or "unknown"
    return {
        "www.gstatic.com": "gstatic",
        "cp.cloudflare.com": "cloudflare",
        "connectivitycheck.platform.hicloud.com": "hicloud",
    }.get(host, host[:64])


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
            answers = await asyncio.wait_for(
                loop.getaddrinfo(
                    config.host,
                    config.port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
                timeout,
            )
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
        values = sorted({answer[4][0].split("%", 1)[0] for answer in answers})
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
            asyncio.open_connection(config.resolved_ip or config.host, config.port), timeout
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


async def _http_probe(port: int, url: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    command = [
        "curl",
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
        stdout, _ = await process.communicate()
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


async def _start_core(
    config: ProxyConfig, core: str, directory: Path
) -> tuple[Any, int, dict[str, Any]]:
    port = _free_port()
    path = directory / "config.json"
    started = time.monotonic()
    try:
        path.write_text(json.dumps(sing_box_config(config, port), separators=(",", ":")))
        path.chmod(0o600)
    except (KeyError, TypeError, ValueError):
        return (
            None,
            port,
            {
                "success": False,
                "category": "CONFIG_REJECTED",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
        )
    try:
        process = await asyncio.create_subprocess_exec(
            core,
            "run",
            "-c",
            str(path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return (
            None,
            port,
            {
                "success": False,
                "category": "SPAWN_ERROR",
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
        )
    if not await _wait_for_core(process, port):
        category = "CORE_EXITED" if process.returncode is not None else "LISTEN_TIMEOUT"
        await _stop_process(process)
        return (
            None,
            port,
            {
                "success": False,
                "category": category,
                "exit_code": process.returncode,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
        )
    return (
        process,
        port,
        {
            "success": True,
            "category": None,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        },
    )


async def _https_session(
    config: ProxyConfig, core: str, attempts: int, required: int
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
                record = await _http_probe(port, target, 4.0)
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


async def _download(port: int, url: str, limit_bps: int) -> dict[str, Any]:
    command = [
        "curl",
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
        stdout, _ = await process.communicate()
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
    success = status in {200, 204, 206} and size >= DOWNLOAD_BYTES * 0.9
    return {
        "success": success,
        "status": status,
        "category": None if success else "DOWNLOAD_SHORT",
        "bytes": size,
        "speed_kbps": round(speed, 2),
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }


async def _direct_control(interface: str) -> dict[str, Any]:
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--connect-timeout",
        "3",
        "--max-time",
        "5",
        "--output",
        os.devnull,
        "--write-out",
        "%{http_code}:%{time_total}",
        PROBE_URLS[0],
    ]
    direct = _direct_socks_address()
    if direct:
        command[4:4] = ["--proxy", f"socks5h://{direct[0]}:{direct[1]}"]
        mode = "direct-socks"
    else:
        command[4:4] = ["--interface", interface]
        mode = "bound-interface"
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await process.communicate()
        status_text, total_text = stdout.decode().split(":", 1)
        success = process.returncode == 0 and 200 <= int(status_text) < 400
        return {
            "success": success,
            "latency_ms": round(float(total_text) * 1000, 2),
            "path_mode": mode,
        }
    except (OSError, UnicodeDecodeError, ValueError):
        return {"success": False, "latency_ms": None, "path_mode": mode}


class DownloadGovernor:
    def __init__(self, concurrency: int, budget_bps: int, interface: str, baseline_ms: float):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.budget_bps = budget_bps
        self.per_transfer_bps = budget_bps // concurrency
        self.interface = interface
        self.baseline_ms = baseline_ms
        self.bytes = 0
        self.active = 0
        self.peak = 0

    async def control(self, factor: float, floor_ms: float) -> dict[str, Any]:
        result = await _direct_control(self.interface)
        limit = max(floor_ms, self.baseline_ms * factor)
        result["congested"] = not result["success"] or (result["latency_ms"] or math.inf) > limit
        return result

    @contextlib.asynccontextmanager
    async def slot(self):
        async with self.semaphore:
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                yield
            finally:
                self.active -= 1


class StageLimiter:
    def __init__(self, limit: int):
        self.semaphore = asyncio.Semaphore(limit)
        self.active = 0
        self.peak = 0
        self.total_ms = 0.0

    @contextlib.asynccontextmanager
    async def slot(self):
        async with self.semaphore:
            started = time.monotonic()
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                yield
            finally:
                self.active -= 1
                self.total_ms += (time.monotonic() - started) * 1000

    def summary(self) -> dict[str, Any]:
        return {"peak_active": self.peak, "total_candidate_ms": round(self.total_ms, 2)}


async def _service_session(
    config: ProxyConfig, core: str, stage: StageLimiter, geo_url: str | None
) -> dict[str, Any]:
    async with stage.slot():
        with tempfile.TemporaryDirectory(prefix="swift-ru-diagnostics-") as raw:
            process, port, core_result = await _start_core(config, core, Path(raw))
            if process is None:
                return {"core": core_result, "results": {}}
            try:
                results = {
                    name: await _http_probe(port, url, 4.0) for name, url in SERVICE_PROBES.items()
                }
                geo = await _geo_probe(port, geo_url) if geo_url else {}
                return {"core": core_result, "results": results, "geo": geo}
            finally:
                await _stop_process(process)


async def _geo_probe(port: int, url: str) -> dict[str, Any]:
    command = [
        "curl",
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
        stdout, _ = await process.communicate()
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
    country = value.get("country") or value.get("loc")
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


def _white_signal(config: ProxyConfig, selected_ip: str, evidence: dict[str, Any]) -> str | None:
    networks = [ipaddress.ip_network(value) for value in evidence.get("networks", [])]
    cidr = any(ipaddress.ip_address(selected_ip) in network for network in networks)
    domains = set(evidence.get("domains", []))
    security = str(config.options.get("security", "none"))
    visible = config.protocol in {"trojan", "hysteria2", "tuic"} or security in {"tls", "reality"}
    name = str(config.options.get("sni") or config.host).lower().rstrip(".") if visible else ""
    labels = name.split(".") if name else []
    sni = any(".".join(labels[index:]) in domains for index in range(max(0, len(labels) - 1)))
    if cidr and sni:
        return "cidr+sni"
    if cidr:
        return "cidr"
    if sni:
        return "sni"
    return None


def _terminal(record: dict[str, Any], reason: str, passed: bool = False) -> dict[str, Any]:
    record["final"] = {
        "terminal_state": TERMINAL_PASS if passed else "FAIL",
        "reason": reason,
        "passed": passed,
        "accounted_for": True,
    }
    record["total_duration_ms"] = round((time.monotonic() - record.pop("_started")) * 1000, 2)
    return record


async def run_generation(root: Path, core: str) -> int:
    generation_dir = root / "data/ru-generation"
    manifest = json.loads((generation_dir / "manifest.json").read_text())
    candidates = read_jsonl(generation_dir / "candidates.jsonl")
    evidence = json.loads((generation_dir / "white-evidence.json").read_text())
    if len(candidates) != manifest["ru_expected"] or len(
        {item["fingerprint"] for item in candidates}
    ) != len(candidates):
        raise RuntimeError("invalid collected generation")
    settings = tomllib.loads((root / "config.toml").read_text())
    ru = settings["ru"]
    positive = (
        "resolution_concurrency",
        "endpoint_concurrency",
        "https_concurrency",
        "stability_concurrency",
        "download_concurrency",
        "diagnostic_concurrency",
    )
    if any(int(ru[key]) < 1 for key in positive):
        raise ValueError("RU stage concurrency must be positive")
    per_transfer_bps = int(ru["download_bandwidth_bps"]) // int(ru["download_concurrency"])
    if per_transfer_bps <= MIN_THROUGHPUT_KBPS * 1024:
        raise ValueError("RU download budget must stay above the quality threshold")
    interface = os.environ.get("SWIFT_BIND_INTERFACE", "")
    if not interface:
        raise RuntimeError("SWIFT_BIND_INTERFACE is required")
    preflight = await _mac_preflight(interface)
    control = await _direct_control(interface)
    publication = root / "data/ru-publication"
    if not preflight.ok or not control["success"]:
        write_json(
            publication / "result-manifest.json",
            {
                **manifest,
                "complete": False,
                "state": "HELD",
                "reason": "RU_PREFLIGHT_FAILED",
                "path_mode": control["path_mode"],
            },
        )
        return 1

    history_path = root / "data/ru-history.json"
    history = (
        json.loads(history_path.read_text())
        if history_path.exists()
        else {"schema_version": 1, "vantage": "ru", "configs": {}}
    )
    if history.get("vantage") != "ru":
        history = {"schema_version": 1, "vantage": "ru", "configs": {}}
    resolution_stage = StageLimiter(int(ru["resolution_concurrency"]))
    endpoint_stage = StageLimiter(int(ru["endpoint_concurrency"]))
    initial_stage = StageLimiter(int(ru["https_concurrency"]))
    stability_stage = StageLimiter(int(ru["stability_concurrency"]))
    diagnostic_stage = StageLimiter(int(ru["diagnostic_concurrency"]))
    governor = DownloadGovernor(
        int(ru["download_concurrency"]),
        int(ru["download_bandwidth_bps"]),
        interface,
        float(control["latency_ms"]),
    )

    async def verify(item: dict[str, Any], retry: bool = False) -> dict[str, Any]:
        config = parse_uri(item["uri"])
        record: dict[str, Any] = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "generation_id": manifest["generation_id"],
            "fingerprint": config.fingerprint,
            "protocol": config.protocol,
            "sources": item["sources"],
            "candidate_sources": item["candidate_sources"],
            "lanes": item["lanes"],
            "retry": retry,
            "_started": time.monotonic(),
            "infrastructure": {
                "path_mode": control["path_mode"],
                "preflight": "PASS",
                "congestion": False,
            },
        }
        async with resolution_stage.slot():
            resolution = await resolve_ru(config, float(ru["resolution_timeout"]))
        record["resolution"] = resolution
        if not resolution["success"]:
            return _terminal(record, resolution["reason"])
        config.resolved_ip = resolution["selected_ip"]
        record["white"] = {
            "upstream_label": bool(item["upstream_white_label"]),
            "evidence": _white_signal(config, config.resolved_ip, evidence),
        }
        async with endpoint_stage.slot():
            endpoint = await endpoint_sanity(config, float(ru["endpoint_timeout"]))
        record["endpoint"] = endpoint
        # Raw TCP is cheap telemetry only. Actual core traffic is authoritative
        # and may use a different direct-dial path.
        async with initial_stage.slot():
            initial, core_start = await _https_session(config, core, 3, 2)
        record["core"] = {"initial": core_start}
        record["https"] = {"initial": initial}
        distinct = {attempt["target"] for attempt in initial if attempt["success"]}
        if len(distinct) < 2:
            record["retry_recommended"] = bool(distinct) or bool(
                history.get("configs", {}).get(config.fingerprint, {}).get("last_pass")
            )
            reason = core_start.get("category") or "HTTPS_FAILED"
            return _terminal(record, reason)
        async with stability_stage.slot():
            stability, stability_core = await _https_session(config, core, 3, 2)
        record["core"]["stability"] = stability_core
        record["https"]["stability"] = stability
        stability_distinct = {attempt["target"] for attempt in stability if attempt["success"]}
        if len(stability_distinct) < 2:
            record["retry_recommended"] = True
            return _terminal(record, stability_core.get("category") or "UNSTABLE")
        latencies = [
            attempt["total_ms"] for attempt in [*initial, *stability] if attempt["success"]
        ]
        record["latency"] = {
            "median_ms": round(statistics.median(latencies), 2),
            "p95_ms": _percentile(latencies, 0.95),
            "jitter_ms": round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0,
        }
        congestion = await governor.control(
            float(ru["congestion_latency_factor"]), float(ru["congestion_latency_floor_ms"])
        )
        record["infrastructure"]["download_control"] = congestion
        if congestion["congested"]:
            record["infrastructure"]["congestion"] = True
            record["retry_recommended"] = True
            return _terminal(record, "DEFER_LOCAL_CONGESTION")
        with tempfile.TemporaryDirectory(prefix="swift-ru-download-") as raw:
            process, port, download_core = await _start_core(config, core, Path(raw))
            record["core"]["download"] = download_core
            if process is None:
                return _terminal(record, download_core.get("category") or "CORE_START_FAILED")
            try:
                async with governor.slot():
                    r1 = await _download(port, DOWNLOAD_URL_R1, governor.per_transfer_bps)
                    governor.bytes += int(r1.get("bytes", 0))
                    record["r1"] = r1
                    if not r1["success"]:
                        control_after = await governor.control(
                            float(ru["congestion_latency_factor"]),
                            float(ru["congestion_latency_floor_ms"]),
                        )
                        record["infrastructure"]["download_control_after"] = control_after
                        if control_after["congested"]:
                            record["retry_recommended"] = True
                            return _terminal(record, "DEFER_LOCAL_CONGESTION")
                        return _terminal(
                            record,
                            "STALLED" if r1["category"] == "STALLED" else "DOWNLOAD_R1_FAILED",
                        )
                    r2 = await _download(port, DOWNLOAD_URL_R2, governor.per_transfer_bps)
                    governor.bytes += int(r2.get("bytes", 0))
                    record["r2"] = r2
            finally:
                await _stop_process(process)
        if not record["r2"]["success"]:
            control_after = await governor.control(
                float(ru["congestion_latency_factor"]),
                float(ru["congestion_latency_floor_ms"]),
            )
            record["infrastructure"]["download_control_after"] = control_after
            if control_after["congested"]:
                record["retry_recommended"] = True
                return _terminal(record, "DEFER_LOCAL_CONGESTION")
            return _terminal(
                record, "STALLED" if record["r2"]["category"] == "STALLED" else "DOWNLOAD_R2_FAILED"
            )
        if min(record["r1"]["speed_kbps"], record["r2"]["speed_kbps"]) < MIN_THROUGHPUT_KBPS:
            control_after = await governor.control(
                float(ru["congestion_latency_factor"]),
                float(ru["congestion_latency_floor_ms"]),
            )
            record["infrastructure"]["download_control_after"] = control_after
            if control_after["congested"]:
                record["retry_recommended"] = True
                return _terminal(record, "DEFER_LOCAL_CONGESTION")
            return _terminal(record, "TOO_SLOW")
        try:
            record["services"] = await asyncio.wait_for(
                _service_session(
                    config,
                    core,
                    diagnostic_stage,
                    str(settings["testing"].get("geo_url") or ""),
                ),
                12.0,
            )
        except TimeoutError:
            record["services"] = {"category": "DIAGNOSTIC_TIMEOUT", "results": {}}
        return _terminal(record, TERMINAL_PASS, True)

    async def bounded(item: dict[str, Any], retry: bool = False) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(
                verify(item, retry=retry), float(ru["per_config_timeout"])
            )
        except ValueError:
            return {
                "schema_version": RESULT_SCHEMA_VERSION,
                "generation_id": manifest["generation_id"],
                "fingerprint": item.get("fingerprint", "INVALID"),
                "protocol": item.get("protocol", "unknown"),
                "sources": item.get("sources", []),
                "candidate_sources": item.get("candidate_sources", []),
                "lanes": item.get("lanes", []),
                "final": {
                    "terminal_state": "FAIL",
                    "reason": "CONFIG_REJECTED",
                    "passed": False,
                    "accounted_for": True,
                },
            }
        except TimeoutError:
            return {
                "schema_version": RESULT_SCHEMA_VERSION,
                "generation_id": manifest["generation_id"],
                "fingerprint": item["fingerprint"],
                "protocol": item["protocol"],
                "sources": item["sources"],
                "candidate_sources": item["candidate_sources"],
                "lanes": item["lanes"],
                "final": {
                    "terminal_state": "FAIL",
                    "reason": "CONFIG_TIMEOUT",
                    "passed": False,
                    "accounted_for": True,
                },
            }

    deadline_at = time.monotonic() + float(ru["run_deadline_seconds"])
    tasks = [asyncio.create_task(bounded(item)) for item in candidates]
    results: list[dict[str, Any]] = []
    complete = True
    run_failure: str | None = None
    try:
        async with asyncio.timeout(max(0.0, deadline_at - time.monotonic())):
            for task in asyncio.as_completed(tasks):
                results.append(await task)
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
        await asyncio.sleep(float(ru["retry_delay_seconds"]))
        retry_items = [item for item in candidates if item["fingerprint"] in retry_by_fp]
        retry_tasks = [asyncio.create_task(bounded(item, retry=True)) for item in retry_items]
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
    deferred = [
        result
        for result in results
        if result.get("final", {}).get("reason") == "DEFER_LOCAL_CONGESTION"
    ]
    result_fps = [result["fingerprint"] for result in results]
    expected_fps = {item["fingerprint"] for item in candidates}
    complete = (
        complete
        and not deferred
        and len(result_fps) == len(expected_fps)
        and len(set(result_fps)) == len(result_fps)
        and set(result_fps) == expected_fps
    )
    performance = {
        "resolution": resolution_stage.summary(),
        "endpoint": endpoint_stage.summary(),
        "initial_https": initial_stage.summary(),
        "stability": stability_stage.summary(),
        "downloads": {"peak_active": governor.peak, "bytes": governor.bytes},
        "diagnostics": diagnostic_stage.summary(),
    }

    write_jsonl(
        publication / "ru-results.jsonl", sorted(results, key=lambda item: item["fingerprint"])
    )
    if not complete:
        write_json(
            publication / "result-manifest.json",
            {
                **manifest,
                "complete": False,
                "state": "RU_INCOMPLETE",
                "accounted_terminal": len(results),
                "untested": len(expected_fps - set(result_fps)),
                "verifier_download_bytes": governor.bytes,
                "path_mode": control["path_mode"],
                "performance": performance,
                "run_failure": run_failure,
            },
        )
        return 1

    now = _now()
    configs_history = history.setdefault("configs", {})
    for result in results:
        rec = configs_history.setdefault(result["fingerprint"], {"observations": []})
        passed = bool(result["final"]["passed"])
        observation = {
            "timestamp": now,
            "vantage": "ru",
            "passed": passed,
            "reason": result["final"]["reason"],
            "latency": result.get("latency"),
            "r1_kbps": result.get("r1", {}).get("speed_kbps"),
            "r2_kbps": result.get("r2", {}).get("speed_kbps"),
        }
        rec["observations"] = [*rec.get("observations", []), observation][-16:]
        rec["last_seen"] = now
        if passed:
            rec["last_pass"] = now
        observations = rec["observations"]
        recent = observations[-4:]
        rec["availability"] = round(
            sum(item["passed"] for item in observations) / len(observations), 4
        )
        rec["recent_availability"] = round(sum(item["passed"] for item in recent) / len(recent), 4)
        rec["consecutive_pass"] = 0
        rec["consecutive_fail"] = 0
        for item in reversed(observations):
            key = "consecutive_pass" if item["passed"] else "consecutive_fail"
            opposite = "consecutive_fail" if item["passed"] else "consecutive_pass"
            if rec[opposite]:
                break
            rec[key] += 1
        rec["confidence"] = round(min(1.0, len(observations) / 8), 4)

    candidate_map = {item["fingerprint"]: item for item in candidates}
    passed = [result for result in results if result["final"]["passed"]]

    def score(result: dict[str, Any]) -> float:
        obs = configs_history[result["fingerprint"]]["observations"]
        availability = sum(item["passed"] for item in obs) / len(obs)
        latency = float(result.get("latency", {}).get("median_ms") or 2000)
        speed = min(float(result["r1"]["speed_kbps"]), float(result["r2"]["speed_kbps"]))
        return round(
            55 * availability + 15 * max(0.0, 1 - latency / 2000) + 20 * min(1.0, speed / 512) + 10,
            2,
        )

    ranked = sorted(passed, key=lambda result: (-math.floor(score(result)), result["fingerprint"]))
    ranked_items: list[RankedConfig] = []
    for result in ranked:
        config = parse_uri(candidate_map[result["fingerprint"]]["uri"])
        test_result = TestResult(
            config.fingerprint,
            "main",
            now,
            success_count=1,
            rounds_attempted=1,
            rounds_succeeded=1,
            median_latency_ms=result["latency"]["median_ms"],
            p95_latency_ms=result["latency"]["p95_ms"],
            jitter_ms=result["latency"]["jitter_ms"],
            throughput_bps=min(result["r1"]["speed_kbps"], result["r2"]["speed_kbps"]) * 1024,
            country=result.get("services", {}).get("geo", {}).get("country"),
            asn=result.get("services", {}).get("geo", {}).get("asn"),
            provider=result.get("services", {}).get("geo", {}).get("provider"),
        )
        ranked_items.append(RankedConfig(config, "main", test_result, score(result), "active", 1.0))
    limits = settings["limits"]
    diversity = settings["diversity"]
    main_pool = [
        item for item in ranked_items if "main" in candidate_map[item.config.fingerprint]["lanes"]
    ]
    white_pool = [
        item
        for item in ranked_items
        if "white" in candidate_map[item.config.fingerprint]["lanes"]
        and (
            white := next(
                result for result in results if result["fingerprint"] == item.config.fingerprint
            ).get("white", {})
        )
        and (white.get("evidence") or white.get("upstream_label"))
    ]
    main = diverse_selection(
        main_pool,
        int(limits["main"]),
        int(diversity["endpoint"]),
        int(diversity["subnet"]),
        int(diversity["asn"]),
    )
    white = diverse_selection(
        white_pool,
        int(limits["white"]),
        int(diversity["endpoint"]),
        int(diversity["subnet"]),
        int(diversity["asn"]),
    )
    output_root = publication / "output"
    write_final_subscriptions(
        output_root,
        subscription_lines(main, ""),
        subscription_lines(white, "W"),
        "https://github.com/femboypig/Swift",
    )
    all_lines = subscription_lines(ranked_items, "A")
    from .output import atomic_write, plain_subscription

    atomic_write(output_root / "sub/all.txt", plain_subscription(all_lines))
    stats = {
        "project": "Swift",
        "updated_at": now,
        "collection_updated_at": manifest["collection_updated_at"],
        "publication_updated_at": now,
        "generation_id": manifest["generation_id"],
        "unique": len(candidates),
        "tested": len(results),
        "alive": len(ranked_items),
        "main": len(main),
        "white": len(white),
        "production": {"main": len(main), "white": len(white), "all": len(ranked_items)},
        "published": False,
        "stage": "ru_complete",
    }
    write_json(output_root / "stats.json", stats)
    write_json(output_root / "data/ru-history.json", history, compact=True)
    postflight = await _mac_preflight(interface)
    complete = postflight.ok
    write_json(
        publication / "result-manifest.json",
        {
            **manifest,
            "complete": complete,
            "state": "RU_COMPLETE" if complete else "HELD",
            "accounted_terminal": len(results),
            "untested": 0,
            "ru_pass": len(ranked_items),
            "main_output": len(main),
            "white_output": len(white),
            "all_output": len(ranked_items),
            "verifier_download_bytes": governor.bytes,
            "path_mode": control["path_mode"],
            "preflight_ok": True,
            "postflight_ok": postflight.ok,
            "performance": performance,
        },
    )
    return 0 if complete else 1


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--core", default=os.environ.get("SWIFT_SING_BOX", ".cache/sing-box/sing-box")
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    core = args.core if Path(args.core).is_absolute() else str(root / args.core)
    return asyncio.run(run_generation(root, core))


if __name__ == "__main__":
    raise SystemExit(cli())
