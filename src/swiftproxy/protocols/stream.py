from __future__ import annotations

import binascii
import json
from urllib.parse import parse_qs, unquote, urlsplit

from swiftproxy.models import ProxyConfig
from swiftproxy.protocols.options import _tls_options, _transport_options
from swiftproxy.protocols.validation import (
    SAFE_TOKEN_RE,
    _b64decode,
    _clean_text,
    _fragment,
    _host,
    _one,
    _port,
    _uuid,
    validate_host,
)


def parse_vless(uri: str) -> ProxyConfig:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    credential = _uuid(unquote(parts.username or ""))
    host = _host(parts)
    port = _port(parts.port)
    transport = _one(query, "type", default="tcp").lower()
    security = _one(query, "security", default="none").lower()
    options = _transport_options(query, transport) | _tls_options(query, security)
    flow = _one(query, "flow")
    if flow:
        if flow != "xtls-rprx-vision":
            raise ValueError("unsupported VLESS flow")
        options["flow"] = flow
    encryption = _one(query, "encryption", default="none")
    if encryption not in {"", "none"}:
        raise ValueError("unsupported VLESS encryption")
    return ProxyConfig("vless", host, port, {"uuid": credential}, options, _fragment(parts))


def parse_vmess(uri: str) -> ProxyConfig:
    encoded = uri.split("://", 1)[1].split("#", 1)[0]
    try:
        raw = json.loads(_b64decode(encoded))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid VMess payload") from exc
    if not isinstance(raw, dict):
        raise ValueError("invalid VMess payload")
    host = _clean_text(str(raw.get("add", "")), 253).lower().rstrip(".")
    validate_host(host)
    port = _port(raw.get("port"))
    credential = _uuid(str(raw.get("id", "")))
    transport = _clean_text(str(raw.get("net", "tcp"))).lower()
    query = {
        "path": [str(raw.get("path", ""))],
        "host": [str(raw.get("host", ""))],
        "serviceName": [str(raw.get("path", "")) if transport == "grpc" else ""],
        "headerType": [str(raw.get("type", ""))],
        "sni": [str(raw.get("sni", ""))],
        "alpn": [str(raw.get("alpn", ""))],
        "fp": [str(raw.get("fp", ""))],
        "allowInsecure": [
            str(
                raw.get(
                    "allowInsecure",
                    raw.get("insecure", raw.get("skip-cert-verify", "")),
                )
            )
        ],
        "packetEncoding": [str(raw.get("packetEncoding", raw.get("packet_encoding", "")))],
    }
    security = str(raw.get("tls", "none")).lower() or "none"
    options = _transport_options(query, transport) | _tls_options(query, security)
    cipher = _clean_text(str(raw.get("scy", raw.get("security", "auto"))))
    try:
        alter_id = int(raw.get("aid", 0) or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid VMess alter ID") from exc
    if alter_id < 0 or alter_id > 65535:
        raise ValueError("invalid VMess alter ID")
    options["cipher"] = cipher
    options["alter_id"] = alter_id
    remark = _clean_text(str(raw.get("ps", "")), 256) if raw.get("ps") else ""
    return ProxyConfig("vmess", host, port, {"uuid": credential}, options, remark)


def parse_trojan(uri: str) -> ProxyConfig:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    password = _clean_text(unquote(parts.username or ""))
    if not password or not SAFE_TOKEN_RE.fullmatch(password):
        raise ValueError("invalid password")
    host = _host(parts)
    port = _port(parts.port)
    transport = _one(query, "type", default="tcp").lower()
    security = _one(query, "security", default="tls").lower()
    options = _transport_options(query, transport) | _tls_options(query, security)
    return ProxyConfig("trojan", host, port, {"password": password}, options, _fragment(parts))


def parse_shadowsocks(uri: str) -> ProxyConfig:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    if _one(query, "plugin"):
        raise ValueError("unsupported Shadowsocks plugin")
    body = uri.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
    if "@" in body:
        userinfo, endpoint = body.rsplit("@", 1)
        try:
            decoded = _b64decode(unquote(userinfo)).decode()
        except (binascii.Error, UnicodeDecodeError):
            decoded = unquote(userinfo)
        endpoint_parts = urlsplit(f"ss://x@{endpoint}")
    else:
        try:
            decoded_all = _b64decode(body).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("invalid Shadowsocks payload") from exc
        if "@" not in decoded_all:
            raise ValueError("invalid Shadowsocks payload")
        decoded, endpoint = decoded_all.rsplit("@", 1)
        endpoint_parts = urlsplit(f"ss://x@{endpoint}")
    if ":" not in decoded:
        raise ValueError("invalid Shadowsocks credentials")
    method, password = decoded.split(":", 1)
    method = _clean_text(method, 64).lower()
    password = _clean_text(password)
    if not method or not password:
        raise ValueError("invalid Shadowsocks credentials")
    return ProxyConfig(
        "ss",
        _host(endpoint_parts),
        _port(endpoint_parts.port),
        {"password": password},
        {"method": method},
        _fragment(parts),
    )
