from __future__ import annotations

import ipaddress
import os
from typing import Any

from swiftproxy.models import ProxyConfig


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


def _direct_socks_address() -> tuple[str, int] | None:
    value = os.environ.get("SWIFT_DIRECT_SOCKS", "").strip()
    if not value:
        return None
    if os.environ.get("SWIFT_BIND_INTERFACE"):
        raise ValueError("SWIFT_DIRECT_SOCKS is incompatible with interface-bound verification")
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ValueError("SWIFT_DIRECT_SOCKS must use HOST:PORT")
    address = ipaddress.ip_address(host)
    port = int(port_text)
    if not address.is_loopback or not 1 <= port <= 65535:
        raise ValueError("SWIFT_DIRECT_SOCKS must point to a loopback port")
    return str(address), port


def sing_box_config(config: ProxyConfig, socks_port: int) -> dict[str, Any]:
    proxy_outbound = sing_box_outbound(config)
    outbounds = [proxy_outbound]
    direct_socks = _direct_socks_address()
    if direct_socks:
        host, port = direct_socks
        proxy_outbound.pop("bind_interface", None)
        proxy_outbound["detour"] = "direct-socks"
        outbounds.append(
            {
                "type": "socks",
                "tag": "direct-socks",
                "server": host,
                "server_port": port,
                "version": "5",
            }
        )
    auto_detect = not bool(os.environ.get("SWIFT_BIND_INTERFACE") or direct_socks)
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
        "outbounds": outbounds,
        "route": {"final": "proxy", "auto_detect_interface": auto_detect},
    }
