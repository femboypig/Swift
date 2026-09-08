from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import os
import signal
import socket
import time
from pathlib import Path
from typing import Any

from swiftproxy.models import ProxyConfig
from swiftproxy.protocols.singbox import sing_box_config


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
    except OSError as exc:
        category = (
            "RESOURCE_ERROR"
            if exc.errno in {errno.EAGAIN, errno.EMFILE, errno.ENFILE, errno.ENOMEM}
            else "SPAWN_ERROR"
        )
        return (
            None,
            port,
            {
                "success": False,
                "category": category,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
        )
    try:
        ready = await _wait_for_core(process, port)
    except BaseException:
        await _stop_process(process)
        raise
    if not ready:
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
