from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from swiftproxy.network import communicate, direct_curl
from swiftproxy.verification.constants import PROBE_URLS
from swiftproxy.verification.core import _free_port, _stop_process, _wait_for_core
from swiftproxy.verification.probes import _http_probe


async def _core_control(core: str, interface: str) -> dict[str, Any]:
    port = _free_port()
    outbound = {
        "type": "direct",
        "tag": "control",
        "bind_interface": interface,
        "domain_resolver": {"server": "direct-dns", "strategy": "prefer_ipv4"},
    }
    value = {
        "log": {"level": "warn", "timestamp": False},
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": "direct-dns",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "path": "/dns-query",
                    "bind_interface": interface,
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                }
            ]
        },
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port}
        ],
        "outbounds": [outbound],
        "route": {"final": "control", "auto_detect_interface": False},
    }
    with tempfile.TemporaryDirectory(prefix="swift-ru-core-control-") as raw:
        path = Path(raw) / "config.json"
        path.write_text(json.dumps(value, separators=(",", ":")))
        path.chmod(0o600)
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
            return {"success": False, "category": "SPAWN_ERROR"}
        try:
            if not await _wait_for_core(process, port):
                return {"success": False, "category": "CORE_EXITED"}
            probe = await _http_probe(port, PROBE_URLS[0], 5.0)
            return {"success": bool(probe["success"]), "category": probe.get("failure")}
        finally:
            await _stop_process(process)


async def _direct_control(interface: str) -> dict[str, Any]:
    mode = "bound-interface"
    try:
        prefix = await direct_curl(PROBE_URLS[0], interface, 5)
    except (OSError, ValueError):
        return {"success": False, "latency_ms": None, "path_mode": mode}
    command = [
        *prefix,
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
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await communicate(process)
        status_text, total_text = stdout.decode().split(":", 1)
        success = process.returncode == 0 and 200 <= int(status_text) < 400
        return {
            "success": success,
            "latency_ms": round(float(total_text) * 1000, 2),
            "path_mode": mode,
        }
    except (OSError, UnicodeDecodeError, ValueError):
        return {"success": False, "latency_ms": None, "path_mode": mode}
