from __future__ import annotations

import html
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from mtproxy_checker.parser import decode_secret

from swiftproxy.models import SourceSpec
from swiftproxy.mtproto.models import TelegramProxy
from swiftproxy.protocols.validation import validate_host

URL_RE = re.compile(r"(?i)(?:https?://t\.me/proxy|tg://proxy)\?[^\s<>\"']+")


def _query(url: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in urlsplit(url).query.split("&"):
        if not part:
            continue
        key, separator, value = part.partition("=")
        key = unquote(key).lower()
        if not separator or key in result:
            raise ValueError("MALFORMED_URL")
        result[key] = unquote(value)
    return result


def _canonical_secret(value: str) -> tuple[str, str]:
    if not value or len(value) > 1024 or any(ord(character) < 33 for character in value):
        raise ValueError("MALFORMED_SECRET")
    try:
        parsed = decode_secret(value)
    except Exception as exc:
        raise ValueError("MALFORMED_SECRET") from exc
    kind = parsed.kind.value
    if kind == "extended-raw":
        raise ValueError("UNSUPPORTED_SECRET")
    if parsed.is_faketls:
        domain = parsed.faketls_domain.lower().rstrip(".")
        try:
            validate_host(domain)
            domain = domain.encode("idna").decode("ascii")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("MALFORMED_SECRET") from exc
        return f"ee{parsed.raw_secret.hex()}{domain.encode().hex()}", "faketls"
    if kind == "dd-secure":
        return f"dd{parsed.raw_secret.hex()}", "secure"
    return parsed.raw_secret.hex(), "raw"


def parse_proxy_url(url: str) -> TelegramProxy:
    url = html.unescape(url.strip()).rstrip(".,;)")
    if len(url) > 2048:
        raise ValueError("MALFORMED_URL")
    parts = urlsplit(url)
    is_tg = parts.scheme.lower() == "tg" and parts.netloc.lower() == "proxy"
    is_web = (
        parts.scheme.lower() in {"http", "https"}
        and (parts.hostname or "").lower() == "t.me"
        and parts.path.rstrip("/").lower() == "/proxy"
    )
    if not is_tg and not is_web:
        raise ValueError("MALFORMED_URL")
    query = _query(url)
    try:
        host = query["server"].strip().removeprefix("[").removesuffix("]").lower().rstrip(".")
        port = int(query["port"])
        secret, secret_kind = _canonical_secret(query["secret"])
    except KeyError as exc:
        raise ValueError("MALFORMED_URL") from exc
    except ValueError as exc:
        if str(exc) in {"MALFORMED_SECRET", "UNSUPPORTED_SECRET"}:
            raise
        raise ValueError("INVALID_PORT") from exc
    if not 1 <= port <= 65535:
        raise ValueError("INVALID_PORT")
    try:
        validate_host(host)
        host = host.encode("idna").decode("ascii")
    except ValueError as exc:
        reason = "PRIVATE_ENDPOINT" if "private" in str(exc) else "INVALID_ENDPOINT"
        raise ValueError(reason) from exc
    except UnicodeError as exc:
        raise ValueError("INVALID_ENDPOINT") from exc
    return TelegramProxy(host, port, secret, secret_kind)


def extract_proxy_urls(text: str) -> list[str]:
    return [match.group(0) for match in URL_RE.finditer(html.unescape(text))]


def deduplicate(proxies: list[TelegramProxy]) -> tuple[list[TelegramProxy], int]:
    unique: dict[str, TelegramProxy] = {}
    duplicates = 0
    for proxy in proxies:
        existing = unique.get(proxy.fingerprint)
        if existing is None:
            unique[proxy.fingerprint] = proxy
        else:
            existing.sources.update(proxy.sources)
            duplicates += 1
    return sorted(unique.values(), key=lambda item: item.fingerprint), duplicates


def telegram_source_specs(settings: dict[str, Any]) -> list[SourceSpec]:
    return [
        SourceSpec(item["id"], item["name"], item["url"], {"telegram"})
        for item in settings["telegram"].get("sources", [])
    ]


def parse_source_results(
    results: list[Any],
) -> tuple[list[TelegramProxy], Counter[str], dict[str, Any]]:
    proxies: list[TelegramProxy] = []
    failures: Counter[str] = Counter()
    source_stats: dict[str, Any] = {}
    for result in results:
        source_id = result.source.source_id
        if result.error:
            source_stats[source_id] = {
                "status": result.error,
                "fetched": 0,
                "unique": 0,
                "working": 0,
            }
            continue
        urls = extract_proxy_urls(result.content)
        seen: set[str] = set()
        for url in urls:
            try:
                proxy = parse_proxy_url(url)
            except ValueError as exc:
                failures[str(exc)] += 1
                continue
            proxy.sources.add(result.source.name)
            proxies.append(proxy)
            seen.add(proxy.fingerprint)
        source_stats[source_id] = {
            "status": "OK" if urls else "EMPTY",
            "fetched": len(urls),
            "unique": len(seen),
            "working": 0,
        }
    return proxies, failures, source_stats


def previous_output_proxies(root: Path) -> list[TelegramProxy]:
    proxies: list[TelegramProxy] = []
    for name in ("all.txt", "stable.txt", "fastest.txt"):
        path = root / "Telegram" / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                proxy = parse_proxy_url(line)
            except ValueError:
                continue
            proxy.sources.add("previous-output")
            proxies.append(proxy)
    return proxies
