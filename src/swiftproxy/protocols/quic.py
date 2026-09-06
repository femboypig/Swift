from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlsplit

from swiftproxy.models import ProxyConfig
from swiftproxy.protocols.options import _tls_options
from swiftproxy.protocols.validation import (
    SAFE_TOKEN_RE,
    _clean_text,
    _flag,
    _fragment,
    _host,
    _one,
    _port,
    _uuid,
)


def parse_hysteria(uri: str) -> ProxyConfig:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    auth = _clean_text(unquote(parts.username or "")) or _one(query, "auth", "auth_str")
    auth = _clean_text(auth) if auth else ""
    options = _tls_options(query, "tls")
    peer = _one(query, "peer", "sni")
    if peer:
        options["sni"] = peer
    alpn = _one(query, "alpn")
    if alpn:
        options["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
    if _flag(query, "insecure", "allowInsecure"):
        options["insecure"] = True
    obfs = _one(query, "obfs")
    if obfs:
        options["obfs"] = obfs
    ports = _one(query, "mport", "ports")
    if ports:
        if not re.fullmatch(r"[0-9,:\-]+", ports):
            raise ValueError("invalid port range")
        options["server_ports"] = [part for part in ports.split(",") if part]
    for query_name, option_name in (
        ("upmbps", "up_mbps"),
        ("downmbps", "down_mbps"),
        ("up", "up_mbps"),
        ("down", "down_mbps"),
    ):
        value = _one(query, query_name)
        if value:
            try:
                bandwidth = int(value)
                if 1 <= bandwidth <= 100000:
                    options[option_name] = bandwidth
            except ValueError:
                pass
    if "up_mbps" not in options:
        options["up_mbps"] = 100
    if "down_mbps" not in options:
        options["down_mbps"] = 100
    return ProxyConfig(
        "hysteria",
        _host(parts),
        _port(parts.port),
        {"auth": auth} if auth else {},
        options,
        _fragment(parts),
    )


def parse_hysteria2(uri: str) -> ProxyConfig:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    username = _clean_text(unquote(parts.username or ""))
    password_part = _clean_text(unquote(parts.password or "")) if parts.password else ""
    password = f"{username}:{password_part}" if password_part else username
    if not password or not SAFE_TOKEN_RE.fullmatch(password):
        raise ValueError("invalid password")
    options = _tls_options(query, "tls")
    obfs = _one(query, "obfs")
    if obfs:
        if obfs != "salamander":
            raise ValueError("unsupported Hysteria2 obfs")
        obfs_password = _one(query, "obfs-password", "obfs_password")
        if not obfs_password:
            raise ValueError("missing Hysteria2 obfs password")
        options["obfs"] = obfs
        options["obfs_password"] = obfs_password
    ports = _one(query, "mport", "ports")
    if ports:
        if not re.fullmatch(r"[0-9,:\-]+", ports):
            raise ValueError("invalid port range")
        options["server_ports"] = [part for part in ports.split(",") if part]
    for query_name, option_name in (("upmbps", "up_mbps"), ("downmbps", "down_mbps")):
        value = _one(query, query_name, option_name)
        if value:
            try:
                bandwidth = int(value)
            except ValueError as exc:
                raise ValueError("invalid Hysteria2 bandwidth") from exc
            if not 1 <= bandwidth <= 100000:
                raise ValueError("invalid Hysteria2 bandwidth")
            options[option_name] = bandwidth
    return ProxyConfig(
        "hysteria2",
        _host(parts),
        _port(parts.port),
        {"password": password},
        options,
        _fragment(parts),
    )


def parse_tuic(uri: str) -> ProxyConfig:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    user = _uuid(unquote(parts.username or ""))
    password = _clean_text(unquote(parts.password or ""))
    if not password or not SAFE_TOKEN_RE.fullmatch(password):
        raise ValueError("invalid password")
    options = _tls_options(query, "tls")
    options["congestion_control"] = _one(
        query, "congestion_control", "congestion-control", default="cubic"
    )
    udp_mode = _one(query, "udp_relay_mode", "udp-relay-mode", default="native")
    if udp_mode not in {"native", "quic"}:
        raise ValueError("unsupported TUIC UDP relay mode")
    options["udp_relay_mode"] = udp_mode
    if _flag(query, "zero_rtt_handshake", "zero-rtt-handshake", "allow_0rtt"):
        options["zero_rtt"] = True
    heartbeat = _one(query, "heartbeat")
    if heartbeat:
        if not re.fullmatch(r"[1-9][0-9]{0,4}(?:ms|s|m)", heartbeat):
            raise ValueError("invalid TUIC heartbeat")
        options["heartbeat"] = heartbeat
    return ProxyConfig(
        "tuic",
        _host(parts),
        _port(parts.port),
        {"uuid": user, "password": password},
        options,
        _fragment(parts),
    )
