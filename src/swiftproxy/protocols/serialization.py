from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlencode

from swiftproxy.models import ProxyConfig


def _endpoint(config: ProxyConfig) -> str:
    host = f"[{config.host}]" if ":" in config.host else config.host
    return f"{host}:{config.port}"


def _common_query(config: ProxyConfig) -> list[tuple[str, str]]:
    options = config.options
    values: list[tuple[str, str]] = []
    aliases = (
        ("transport", "type"),
        ("security", "security"),
        ("flow", "flow"),
        ("sni", "sni"),
        ("fingerprint", "fp"),
        ("public_key", "pbk"),
        ("short_id", "sid"),
        ("spider_x", "spx"),
        ("packet_encoding", "packetEncoding"),
        ("path", "path"),
        ("host_header", "host"),
        ("service_name", "serviceName"),
        ("grpc_mode", "mode"),
        ("header_type", "headerType"),
    )
    for key, alias in aliases:
        value = options.get(key)
        if value not in {None, ""}:
            values.append((alias, str(value)))
    if options.get("alpn"):
        values.append(("alpn", ",".join(options["alpn"])))
    if options.get("insecure"):
        values.append(("insecure", "1"))
    return values


def serialize_uri(config: ProxyConfig, name: str | None = None) -> str:
    fragment = quote(name if name is not None else config.remark, safe="")
    suffix = f"#{fragment}" if fragment else ""
    endpoint = _endpoint(config)
    if config.protocol == "vless":
        query = [("encryption", "none"), *_common_query(config)]
        return f"vless://{quote(str(config.auth['uuid']), safe='')}@{endpoint}?{urlencode(query)}{suffix}"
    if config.protocol == "vmess":
        options = config.options
        data: dict[str, Any] = {
            "v": "2",
            "ps": name if name is not None else config.remark,
            "add": config.host,
            "port": config.port,
            "id": config.auth["uuid"],
            "aid": options.get("alter_id", 0),
            "scy": options.get("cipher", "auto"),
            "net": options.get("transport", "tcp"),
            "type": options.get("header_type", "none"),
            "host": options.get("host_header", ""),
            "path": options.get("service_name")
            if options.get("transport") == "grpc"
            else options.get("path", ""),
            "tls": "tls" if options.get("security") == "tls" else "",
            "sni": options.get("sni", ""),
            "alpn": ",".join(options.get("alpn", [])),
            "fp": options.get("fingerprint", ""),
            "allowInsecure": bool(options.get("insecure", False)),
            "packetEncoding": options.get("packet_encoding", ""),
        }
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        return "vmess://" + base64.b64encode(raw).decode()
    if config.protocol == "trojan":
        query = _common_query(config)
        return f"trojan://{quote(str(config.auth['password']), safe='')}@{endpoint}?{urlencode(query)}{suffix}"
    if config.protocol == "ss":
        credentials = f"{config.options['method']}:{config.auth['password']}".encode()
        encoded = base64.urlsafe_b64encode(credentials).decode().rstrip("=")
        return f"ss://{encoded}@{endpoint}{suffix}"
    if config.protocol == "hysteria":
        query = [
            (key, value) for key, value in _common_query(config) if key not in {"security", "type"}
        ]
        if config.auth.get("auth"):
            query.append(("auth", str(config.auth["auth"])))
        if config.options.get("obfs"):
            query.append(("obfs", str(config.options["obfs"])))
        if config.options.get("server_ports"):
            query.append(("mport", ",".join(config.options["server_ports"])))
        if config.options.get("up_mbps"):
            query.append(("upmbps", str(config.options["up_mbps"])))
        if config.options.get("down_mbps"):
            query.append(("downmbps", str(config.options["down_mbps"])))
        mark = f"?{urlencode(query)}" if query else ""
        return f"hysteria://{endpoint}{mark}{suffix}"
    if config.protocol == "hysteria2":
        query = [
            (key, value) for key, value in _common_query(config) if key not in {"security", "type"}
        ]
        if config.options.get("obfs"):
            query.extend(
                [
                    ("obfs", str(config.options["obfs"])),
                    ("obfs-password", str(config.options["obfs_password"])),
                ]
            )
        if config.options.get("server_ports"):
            query.append(("mport", ",".join(config.options["server_ports"])))
        if config.options.get("up_mbps"):
            query.append(("upmbps", str(config.options["up_mbps"])))
        if config.options.get("down_mbps"):
            query.append(("downmbps", str(config.options["down_mbps"])))
        mark = f"?{urlencode(query)}" if query else ""
        return (
            f"hysteria2://{quote(str(config.auth['password']), safe='')}@{endpoint}{mark}{suffix}"
        )
    if config.protocol == "tuic":
        query = [
            (key, value) for key, value in _common_query(config) if key not in {"security", "type"}
        ]
        query.extend(
            [
                ("congestion_control", str(config.options.get("congestion_control", "cubic"))),
                ("udp_relay_mode", str(config.options.get("udp_relay_mode", "native"))),
            ]
        )
        if config.options.get("zero_rtt"):
            query.append(("zero_rtt_handshake", "1"))
        if config.options.get("heartbeat"):
            query.append(("heartbeat", str(config.options["heartbeat"])))
        user = quote(str(config.auth["uuid"]), safe="")
        password = quote(str(config.auth["password"]), safe="")
        return f"tuic://{user}:{password}@{endpoint}?{urlencode(query)}{suffix}"
    raise ValueError(f"cannot serialize {config.protocol}")
