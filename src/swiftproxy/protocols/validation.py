from __future__ import annotations

import base64
import ipaddress
import re
import uuid
from typing import Any
from urllib.parse import unquote

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


SAFE_TOKEN_RE = re.compile(r"^[^\x00-\x20\x7f]{1,1024}$")


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


LOCAL_NAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}


LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


def _b64decode(value: str) -> bytes:
    compact = "".join(value.split()).replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    return base64.b64decode(compact, validate=True)


def _clean_text(value: str, limit: int = 1024) -> str:
    value = value.strip()
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


def _fragment(parts: Any) -> str:
    return _clean_text(unquote(parts.fragment), 256) if parts.fragment else ""
