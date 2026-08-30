from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import math
import os
import signal
import socket
import statistics
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from collections.abc import Callable
from typing import Any

from .models import ProxyConfig, TestResult
from .parsing import parse_uri, serialize_uri


LOGGER = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


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
            answers = await loop.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise ValueError("DNS_FAILED") from exc
        addresses = sorted({answer[4][0].split("%", 1)[0] for answer in answers})
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


async def resolve_public_endpoint(
    config: ProxyConfig,
    prefer: Callable[[str], bool] | None = None,
) -> str:
    config.resolved_ip = await resolve_public_host(config.host, config.port, prefer)
    return config.resolved_ip


async def resolve_candidates(
    configs: list[ProxyConfig],
    concurrency: int = 100,
    timeout: float = 8.0,
    prefer: Callable[[str], bool] | None = None,
) -> tuple[list[ProxyConfig], dict[str, str]]:
    semaphore = asyncio.Semaphore(concurrency)
    failures: dict[str, str] = {}

    async def resolve(config: ProxyConfig) -> None:
        async with semaphore:
            try:
                await asyncio.wait_for(resolve_public_endpoint(config, prefer), timeout)
            except TimeoutError:
                failures[config.fingerprint] = "DNS_TIMEOUT"
            except ValueError as exc:
                failures[config.fingerprint] = str(exc)

    await asyncio.gather(*(resolve(config) for config in configs))
    return [config for config in configs if config.fingerprint not in failures], failures


async def cheap_connectivity(config: ProxyConfig, timeout: float) -> bool:
    if config.protocol in {"hysteria2", "tuic"}:
        return True
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(config.resolved_ip or config.host, config.port), timeout
        )
    except (TimeoutError, OSError):
        return False
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return True


def _tls(config: ProxyConfig, required: bool = False) -> dict[str, Any] | None:
    options = config.options
    security = options.get("security", "none")
    if security == "none" and not required:
        return None
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": options.get("sni") or config.host,
        "insecure": bool(options.get("insecure", False)),
    }
    if options.get("alpn"):
        tls["alpn"] = options["alpn"]
    fingerprint = options.get("fingerprint")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": options["public_key"],
            "short_id": options.get("short_id", ""),
        }
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def _transport(config: ProxyConfig) -> dict[str, Any] | None:
    options = config.options
    transport = options.get("transport", "tcp")
    if transport == "tcp":
        return None
    value: dict[str, Any] = {"type": transport}
    if transport == "http":
        if options.get("host_header"):
            value["host"] = [options["host_header"]]
        if options.get("path"):
            value["path"] = options["path"]
    elif transport in {"ws", "httpupgrade"}:
        if options.get("path"):
            value["path"] = options["path"]
        if options.get("host_header"):
            value["headers"] = {"Host": options["host_header"]}
    elif transport == "grpc":
        value["service_name"] = options.get("service_name", "")
    elif transport != "quic":
        raise ValueError("unsupported transport")
    return value


def sing_box_outbound(config: ProxyConfig) -> dict[str, Any]:
    server = config.resolved_ip or config.host
    base: dict[str, Any] = {
        "type": config.protocol if config.protocol != "ss" else "shadowsocks",
        "tag": "proxy",
        "server": server,
        "server_port": config.port,
    }
    if bind_iface := os.environ.get("SWIFT_BIND_INTERFACE"):
        base["bind_interface"] = bind_iface
    options = config.options
    if config.protocol in {"vless", "vmess"} and options.get("packet_encoding"):
        base["packet_encoding"] = options["packet_encoding"]
    if config.protocol == "vless":
        base["uuid"] = config.auth["uuid"]
        if options.get("flow"):
            base["flow"] = options["flow"]
        if tls := _tls(config):
            base["tls"] = tls
        if transport := _transport(config):
            base["transport"] = transport
    elif config.protocol == "vmess":
        base.update(
            {
                "uuid": config.auth["uuid"],
                "security": options.get("cipher", "auto"),
                "alter_id": options.get("alter_id", 0),
            }
        )
        if tls := _tls(config):
            base["tls"] = tls
        if transport := _transport(config):
            base["transport"] = transport
    elif config.protocol == "trojan":
        base["password"] = config.auth["password"]
        if tls := _tls(config, required=True):
            base["tls"] = tls
        if transport := _transport(config):
            base["transport"] = transport
    elif config.protocol == "ss":
        base["method"] = options["method"]
        base["password"] = config.auth["password"]
    elif config.protocol == "hysteria":
        if config.auth.get("auth"):
            base["auth_str"] = config.auth["auth"]
        base["up_mbps"] = options.get("up_mbps", 100)
        base["down_mbps"] = options.get("down_mbps", 100)
        if options.get("obfs"):
            base["obfs"] = options["obfs"]
        if options.get("server_ports"):
            base.pop("server_port")
            base["server_ports"] = options["server_ports"]
        base["tls"] = _tls(config, required=True)
    elif config.protocol == "hysteria2":
        base["password"] = config.auth["password"]
        base["tls"] = _tls(config, required=True)
        if options.get("server_ports"):
            base.pop("server_port")
            base["server_ports"] = options["server_ports"]
        if options.get("obfs"):
            base["obfs"] = {
                "type": options["obfs"],
                "password": options["obfs_password"],
            }
        if options.get("up_mbps"):
            base["up_mbps"] = options["up_mbps"]
        if options.get("down_mbps"):
            base["down_mbps"] = options["down_mbps"]
    elif config.protocol == "tuic":
        base.update(
            {
                "uuid": config.auth["uuid"],
                "password": config.auth["password"],
                "congestion_control": options.get("congestion_control", "cubic"),
                "udp_relay_mode": options.get("udp_relay_mode", "native"),
                "zero_rtt_handshake": bool(options.get("zero_rtt", False)),
                "tls": _tls(config, required=True),
            }
        )
        if options.get("heartbeat"):
            base["heartbeat"] = options["heartbeat"]
    else:
        raise ValueError("unsupported protocol")
    return base


def sing_box_config(config: ProxyConfig, socks_port: int) -> dict[str, Any]:
    auto_detect = not bool(os.environ.get("SWIFT_BIND_INTERFACE"))
    return {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }
        ],
        "outbounds": [sing_box_outbound(config)],
        "route": {"final": "proxy", "auto_detect_interface": auto_detect},
    }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _wait_for_core(process: asyncio.subprocess.Process, port: int) -> bool:
    for _ in range(40):
        if process.returncode is not None:
            return False
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    return False


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(process.wait(), 2.0)
        return
    except TimeoutError:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        await process.wait()


async def _curl(
    socks_port: int,
    url: str,
    connect_timeout: float,
    request_timeout: float,
    output: Path | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any] | None:
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout",
        str(connect_timeout),
        "--max-time",
        str(request_timeout),
        "--output",
        str(output) if output else os.devnull,
        "--write-out",
        "%{json}",
    ]
    if max_bytes:
        command.extend(["--max-filesize", str(max_bytes)])
    command.append(url)
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    if process.returncode != 0:
        return None
    try:
        metrics = json.loads(stdout)
        status = int(metrics.get("response_code", 0))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not 200 <= status < 400:
        return None
    return metrics


async def _probe(
    socks_port: int, url: str, settings: dict[str, Any]
) -> tuple[float, float, float] | None:
    metrics = await _curl(
        socks_port,
        url,
        float(settings["connect_timeout"]),
        float(settings["request_timeout"]),
        max_bytes=128 * 1024,
    )
    if not metrics:
        return None
    total = float(metrics.get("time_total", 0)) * 1000
    connect = float(metrics.get("time_appconnect") or metrics.get("time_connect", 0)) * 1000
    response = float(metrics.get("time_starttransfer", 0)) * 1000
    if total <= 0:
        return None
    return total, connect, response


async def _throughput(socks_port: int, settings: dict[str, Any]) -> float | None:
    size = int(settings["download_bytes"])
    url = str(settings["download_url"]).replace("{bytes}", str(size))
    metrics = await _curl(
        socks_port,
        url,
        float(settings["connect_timeout"]),
        float(settings["download_timeout"]),
        max_bytes=size + 1024,
    )
    if not metrics or float(metrics.get("size_download", 0)) < size * 0.8:
        return None
    speed = float(metrics.get("speed_download", 0))
    return speed if speed > 0 else None


async def _geo(socks_port: int, settings: dict[str, Any], directory: Path) -> dict[str, Any]:
    url = settings.get("geo_url")
    if not url:
        return {}
    path = directory / "geo.json"
    metrics = await _curl(
        socks_port,
        str(url),
        float(settings["connect_timeout"]),
        float(settings["request_timeout"]),
        output=path,
        max_bytes=64 * 1024,
    )
    if not metrics:
        return {}
    try:
        content = path.read_text()
    except OSError:
        return {}
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        value = {}
        for line in content.splitlines():
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


def _finish_latency_metrics(result: TestResult) -> None:
    if not result.latencies_ms:
        return
    result.median_latency_ms = statistics.median(result.latencies_ms)
    result.p95_latency_ms = _percentile(result.latencies_ms, 0.95)
    result.min_latency_ms = min(result.latencies_ms)
    result.max_latency_ms = max(result.latencies_ms)
    result.jitter_ms = (
        statistics.pstdev(result.latencies_ms) if len(result.latencies_ms) > 1 else 0.0
    )
    result.median_connect_ms = statistics.median(result.connect_times_ms)
    result.median_response_ms = statistics.median(result.response_times_ms)


def _minimum_throughput(lane: str, settings: dict[str, Any]) -> float:
    return float(settings[f"{lane}_min_throughput_bps"])


async def _test_round(
    config: ProxyConfig,
    lane: str,
    core_path: str,
    settings: dict[str, Any],
    result: TestResult,
    directory: Path,
    round_index: int,
) -> tuple[str | None, float | None]:
    result.rounds_attempted += 1
    socks_port = _free_port()
    config_path = directory / f"config-{round_index}.json"
    config_path.write_text(json.dumps(sing_box_config(config, socks_port), separators=(",", ":")))
    process = await asyncio.create_subprocess_exec(
        core_path,
        "run",
        "-c",
        str(config_path),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        if not await _wait_for_core(process, socks_port):
            return "CORE_START_FAILED", None
        targets = settings["white_probe_urls"] if lane == "white" else settings["probe_urls"]
        probes = int(settings["probes"])
        offset = (int(config.fingerprint[:8], 16) + round_index * probes) % len(targets)
        round_successes = 0
        for index in range(probes):
            target = targets[(offset + index) % len(targets)]
            measurement = await _probe(socks_port, target, settings)
            if measurement is None:
                result.failure_count += 1
                continue
            latency, connect, response = measurement
            round_successes += 1
            result.success_count += 1
            result.latencies_ms.append(latency)
            result.connect_times_ms.append(connect)
            result.response_times_ms.append(response)
        if round_successes / probes < float(settings["throughput_probe_ratio"]):
            return None, None
        throughput = await _throughput(socks_port, settings)
        if throughput is not None and throughput >= _minimum_throughput(lane, settings):
            result.rounds_succeeded += 1
        if result.country is None:
            geo = await _geo(socks_port, settings, directory)
            result.country = geo.get("country")
            result.asn = geo.get("asn")
            result.provider = geo.get("provider")
        return None, throughput
    finally:
        await _stop_process(process)


async def test_config(
    config: ProxyConfig,
    lane: str,
    core_path: str,
    settings: dict[str, Any],
) -> TestResult:
    result = TestResult(config.fingerprint, lane, _now())
    if not await cheap_connectivity(config, float(settings["connect_timeout"])):
        result.reason = "CONNECT_TIMEOUT"
        return result

    published = parse_uri(serialize_uri(config))
    if published.fingerprint != config.fingerprint:
        raise RuntimeError("serialized config changed its fingerprint")
    published.resolved_ip = config.resolved_ip

    core_failures = 0
    throughputs: list[float] = []
    with tempfile.TemporaryDirectory(prefix="swift-test-") as raw_directory:
        directory = Path(raw_directory)
        for round_index in range(int(settings["rounds"])):
            error, throughput = await _test_round(
                published,
                lane,
                core_path,
                settings,
                result,
                directory,
                round_index,
            )
            if error == "CORE_START_FAILED":
                core_failures += 1
            if throughput is not None:
                throughputs.append(throughput)

    _finish_latency_metrics(result)
    if throughputs:
        result.throughput_bps = min(throughputs)
    if core_failures == result.rounds_attempted:
        result.reason = "CORE_START_FAILED"
    elif result.success_count == 0:
        result.reason = "PROXY_FAILED"
    elif result.success_ratio < 0.8:
        result.reason = "UNSTABLE"
    elif len(throughputs) < result.rounds_attempted:
        result.reason = "HTTP_FAILED"
    elif result.throughput_bps < _minimum_throughput(lane, settings):
        result.reason = "TOO_SLOW"
    elif not result.confirmed:
        result.reason = "UNSTABLE"
    return result


async def test_candidates(
    jobs: list[tuple[ProxyConfig, str]],
    core_path: str,
    settings: dict[str, Any],
) -> list[TestResult]:
    semaphore = asyncio.Semaphore(int(settings["concurrency"]))
    results: list[TestResult] = []
    completed = 0

    async def run(config: ProxyConfig, lane: str) -> None:
        nonlocal completed
        async with semaphore:
            try:
                result = await asyncio.wait_for(
                    test_config(config, lane, core_path, settings),
                    timeout=float(settings["per_config_timeout"]),
                )
            except TimeoutError:
                result = TestResult(config.fingerprint, lane, _now(), reason="PROXY_TIMEOUT")
            results.append(result)
            completed += 1
            if completed % 50 == 0 or completed == len(jobs):
                alive = sum(item.worked for item in results)
                LOGGER.info("testing progress=%d/%d alive=%d", completed, len(jobs), alive)

    tasks = [asyncio.create_task(run(config, lane)) for config, lane in jobs]
    try:
        async with asyncio.timeout(float(settings["global_timeout"])):
            await asyncio.gather(*tasks)
    except TimeoutError:
        LOGGER.error("GLOBAL_TIMEOUT completed=%d total=%d", completed, len(jobs))
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def preflight_targets(settings: dict[str, Any]) -> bool:
    targets = list(dict.fromkeys([*settings["probe_urls"], *settings["white_probe_urls"]]))

    async def check(url: str) -> bool:
        process = await asyncio.create_subprocess_exec(
            "curl",
            "--silent",
            "--show-error",
            "--location",
            "--output",
            os.devnull,
            "--connect-timeout",
            str(settings["connect_timeout"]),
            "--max-time",
            str(settings["request_timeout"]),
            "--write-out",
            "%{response_code}",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await process.communicate()
        return process.returncode == 0 and stdout[:1] in {b"2", b"3"}

    reachable = sum(await asyncio.gather(*(check(url) for url in targets)))
    download_url = str(settings["download_url"]).replace("{bytes}", "1024")
    download_reachable = await check(download_url)
    LOGGER.info(
        "target preflight reachable=%d total=%d download=%s",
        reachable,
        len(targets),
        download_reachable,
    )
    return reachable >= min(2, len(targets)) and download_reachable
