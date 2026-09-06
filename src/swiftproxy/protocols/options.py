from __future__ import annotations

import re
from typing import Any

from swiftproxy.protocols.validation import SAFE_TOKEN_RE, _flag, _one

TRANSPORTS = {"tcp", "http", "ws", "grpc", "httpupgrade", "quic"}


TRANSPORT_ALIASES = {"raw": "tcp", "websocket": "ws"}


def _transport_options(query: dict[str, list[str]], transport: str) -> dict[str, Any]:
    transport = TRANSPORT_ALIASES.get(transport, transport)
    if transport not in TRANSPORTS:
        raise ValueError("unsupported transport")
    options: dict[str, Any] = {"transport": transport}
    path = _one(query, "path")
    host_header = _one(query, "host")
    service_name = _one(query, "serviceName", "service_name")
    mode = _one(query, "mode")
    header_type = _one(query, "headerType", "header_type")
    if transport == "tcp" and header_type not in {"", "none"}:
        raise ValueError("unsupported TCP header")
    if transport == "grpc" and mode not in {"", "gun"}:
        raise ValueError("unsupported gRPC mode")
    if path:
        options["path"] = path
    if host_header:
        options["host_header"] = host_header
    if service_name:
        options["service_name"] = service_name
    if mode:
        options["grpc_mode"] = mode
    if header_type and header_type != "none":
        options["header_type"] = header_type
    packet_encoding = _one(query, "packetEncoding", "packet_encoding").lower()
    if packet_encoding:
        if packet_encoding not in {"packetaddr", "xudp"}:
            raise ValueError("unsupported packet encoding")
        options["packet_encoding"] = packet_encoding
    return options


def _tls_options(query: dict[str, list[str]], security: str) -> dict[str, Any]:
    if security not in {"", "none", "tls", "reality"}:
        raise ValueError("unsupported security")
    options: dict[str, Any] = {"security": security or "none"}
    sni = _one(query, "sni", "serverName", "peer")
    alpn = _one(query, "alpn")
    fingerprint = _one(query, "fp", "fingerprint")
    if sni:
        options["sni"] = sni
    if alpn:
        values = [item.strip() for item in alpn.split(",") if item.strip()]
        if values:
            options["alpn"] = values
    if fingerprint:
        options["fingerprint"] = fingerprint
    if _flag(query, "allowInsecure", "insecure", "skip-cert-verify"):
        options["insecure"] = True
    if security == "reality":
        public_key = _one(query, "pbk", "publicKey", "public_key")
        if not public_key or not SAFE_TOKEN_RE.fullmatch(public_key):
            raise ValueError("missing Reality public key")
        options["public_key"] = public_key
        short_id = _one(query, "sid", "shortId", "short_id")
        if short_id:
            if not re.fullmatch(r"[0-9a-fA-F]{1,16}", short_id):
                raise ValueError("invalid Reality short ID")
            options["short_id"] = short_id.lower()
        spider_x = _one(query, "spx", "spiderX", "spider_x")
        if spider_x:
            options["spider_x"] = spider_x
    return options
