from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import uuid
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

from .models import ProxyConfig, SourceResult


SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")
URI_RE = re.compile(r"(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s<>\"']+")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SAFE_TOKEN_RE = re.compile(r"^[^\x00-\x20\x7f]{1,1024}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)
LOCAL_NAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}
LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
TRANSPORTS = {"tcp", "http", "ws", "grpc", "httpupgrade", "quic"}
TRANSPORT_ALIASES = {"raw": "tcp", "websocket": "ws"}


def _b64decode(value: str) -> bytes:
    compact = "".join(value.split()).replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    return base64.b64decode(compact, validate=True)


def _clean_text(value: str, limit: int = 1024) -> str:
    value = unquote(value).strip()
    if CONTROL_RE.search(value) or len(value) > limit:
        raise ValueError("control character or oversized value")
    return value


def _one(query: dict[str, list[str]], *names: str, default: str = "") -> str:
    lowered = {key.lower(): values for key, values in query.items()}
    for name in names:
        values = lowered.get(name.lower())
        if values:
            return _clean_text(values[-1])
    return default


def _flag(query: dict[str, list[str]], *names: str) -> bool:
    return _one(query, *names).lower() in {"1", "true", "yes"}


def _port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return port


def _host(parts: Any) -> str:
    try:
        host = parts.hostname
    except ValueError as exc:
        raise ValueError("invalid endpoint") from exc
    if not host:
        raise ValueError("missing host")
    host = _clean_text(host, 253).lower().rstrip(".")
    validate_host(host)
    return host


def validate_host(host: str) -> None:
    lowered = host.lower().rstrip(".")
    if lowered in LOCAL_NAMES or lowered.endswith(LOCAL_SUFFIXES):
        raise ValueError("private endpoint")
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        try:
            ascii_host = lowered.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid endpoint") from exc
        if not DOMAIN_RE.fullmatch(ascii_host):
            raise ValueError("invalid endpoint")
        return
    if not address.is_global:
        raise ValueError("private endpoint")


def _uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise ValueError("invalid UUID") from exc


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
    alter_id = int(raw.get("aid", 0) or 0)
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
        "tuic", _host(parts), _port(parts.port), {"uuid": user, "password": password}, options,
        _fragment(parts)
    )


def _fragment(parts: Any) -> str:
    return _clean_text(parts.fragment, 256) if parts.fragment else ""


def parse_uri(uri: str) -> ProxyConfig:
    uri = uri.strip()
    if not uri or len(uri) > 8192 or CONTROL_RE.search(uri):
        raise ValueError("malformed URI")
    scheme = uri.split(":", 1)[0].lower()
    parsers = {
        "vless": parse_vless,
        "vmess": parse_vmess,
        "trojan": parse_trojan,
        "ss": parse_shadowsocks,
        "hysteria2": parse_hysteria2,
        "hy2": parse_hysteria2,
        "tuic": parse_tuic,
    }
    parser = parsers.get(scheme)
    if not parser:
        raise ValueError("unsupported protocol")
    return parser(uri)


def extract_uris(content: str, content_type: str = "auto") -> list[str]:
    if len(content) > 20_000_000:
        raise ValueError("source is too large")
    candidates: list[str] = []
    for line in content.replace("\ufeff", "").splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if any(lowered.startswith(f"{scheme}://") for scheme in SCHEMES):
            candidates.append(stripped)
            continue
        if content_type == "html" or "://" in stripped:
            candidates.extend(match.group(0) for match in URI_RE.finditer(stripped))
    if candidates or content_type == "html":
        return candidates
    compact = "".join(content.split())
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return []
    try:
        decoded = _b64decode(compact).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return []
    return extract_uris(decoded, "plain")


def parse_sources(results: list[SourceResult]) -> tuple[list[ProxyConfig], Counter[str], int]:
    parsed: list[ProxyConfig] = []
    reasons: Counter[str] = Counter()
    collected = 0
    for result in results:
        if result.error:
            reasons["SOURCE_FAILED"] += 1
            continue
        uris = extract_uris(result.content, result.source.content_type)
        if not uris:
            reasons["SOURCE_EMPTY"] += 1
        collected += len(uris)
        for uri in uris:
            try:
                config = parse_uri(uri)
            except ValueError as exc:
                message = str(exc)
                if "private endpoint" in message:
                    reasons["PRIVATE_ENDPOINT"] += 1
                elif "unsupported" in message:
                    reasons["UNSUPPORTED"] += 1
                else:
                    reasons["PARSE_ERROR"] += 1
                continue
            config.sources.add(result.source.name)
            config.lanes.update(result.source.lanes)
            parsed.append(config)
    return parsed, reasons, collected


def deduplicate(configs: list[ProxyConfig]) -> tuple[list[ProxyConfig], int]:
    unique: dict[str, ProxyConfig] = {}
    duplicates = 0
    for config in configs:
        existing = unique.get(config.fingerprint)
        if existing is None:
            unique[config.fingerprint] = config
            continue
        existing.sources.update(config.sources)
        existing.lanes.update(config.lanes)
        duplicates += 1
    return list(unique.values()), duplicates


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
    if config.protocol == "hysteria2":
        query = [(key, value) for key, value in _common_query(config) if key not in {"security", "type"}]
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
        return f"hysteria2://{quote(str(config.auth['password']), safe='')}@{endpoint}{mark}{suffix}"
    if config.protocol == "tuic":
        query = [(key, value) for key, value in _common_query(config) if key not in {"security", "type"}]
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
