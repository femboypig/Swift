from __future__ import annotations

import binascii
import re
from collections import Counter

from swiftproxy.models import ProxyConfig, SourceResult
from swiftproxy.protocols.parser import SUPPORTED_PROXY_SCHEMES, parse_uri
from swiftproxy.protocols.validation import _b64decode

SCHEMES = tuple(sorted(SUPPORTED_PROXY_SCHEMES))


URI_RE = re.compile(r"(?i)(?:vless|vmess|trojan|ss|hysteria|hysteria2|hy2|tuic)://[^\s<>\"']+")


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
