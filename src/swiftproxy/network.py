from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlencode, urlsplit


def curl_command() -> list[str]:
    return [
        "curl",
        "-q",
        "--noproxy",
        "",
        "--proxy",
        "",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
    ]


def validate_interface(interface: str) -> None:
    if os.environ.get("SWIFT_DIRECT_SOCKS"):
        raise ValueError("SWIFT_DIRECT_SOCKS is incompatible with direct verification")
    if (
        not interface
        or "/" in interface
        or not (Path("/sys/class/net") / interface / "device").exists()
    ):
        raise ValueError("verification requires a physical Linux network interface")
    socket.if_nametoindex(interface)
    route = subprocess.run(
        ["ip", "-json", "route", "get", "1.1.1.1", "oif", interface],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    routes = json.loads(route.stdout)
    if not routes or routes[0].get("dev") != interface:
        raise ValueError("no direct route on the verification interface")


async def communicate(process: asyncio.subprocess.Process) -> tuple[bytes, bytes | None]:
    try:
        return await process.communicate()
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()


async def resolve_direct(host: str, interface: str, timeout: float = 8) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass

    async def query(record_type: int) -> list[str]:
        query_string = urlencode({"name": host.encode("idna").decode(), "type": record_type})
        process = await asyncio.create_subprocess_exec(
            *curl_command(),
            "--interface",
            f"if!{interface}",
            "--resolve",
            "cloudflare-dns.com:443:1.1.1.1",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            str(timeout),
            "--max-filesize",
            "65536",
            "--header",
            "Accept: application/dns-json",
            f"https://cloudflare-dns.com/dns-query?{query_string}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await communicate(process)
        if process.returncode:
            raise OSError("direct DNS request failed")
        try:
            data = json.loads(stdout)
            if data["Status"] != 0 or data.get("TC"):
                raise ValueError("unsuccessful DNS response")
            return [
                str(ipaddress.ip_address(answer["data"]))
                for answer in data.get("Answer", [])
                if answer["type"] == record_type
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise OSError("invalid direct DNS response") from exc

    answers = await asyncio.gather(query(1), query(28), return_exceptions=True)
    addresses: list[str] = []
    for answer in answers:
        if isinstance(answer, BaseException):
            raise OSError("direct DNS resolution failed") from answer
        addresses.extend(answer)
    addresses = sorted(set(addresses))
    if not addresses:
        raise OSError("direct DNS returned no addresses")
    return addresses


async def direct_curl(url: str, interface: str, timeout: float = 8) -> list[str]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("direct control requires an HTTPS URL")
    addresses = await resolve_direct(parts.hostname, interface, timeout)
    public = [value for value in addresses if ipaddress.ip_address(value).is_global]
    if len(public) != len(addresses):
        raise OSError("unsafe direct control address")
    values = ",".join(f"[{value}]" if ":" in value else value for value in public)
    return [
        *curl_command(),
        "--interface",
        f"if!{interface}",
        "--resolve",
        f"{parts.hostname}:{parts.port or 443}:{values}",
        "--max-redirs",
        "0",
    ]


async def open_connection(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    interface = os.environ.get("SWIFT_BIND_INTERFACE")
    if not interface:
        return await asyncio.open_connection(host, port)
    address = ipaddress.ip_address(host)
    sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_connect(sock, (str(address), port))
        return await asyncio.open_connection(sock=sock)
    except BaseException:
        sock.close()
        raise
