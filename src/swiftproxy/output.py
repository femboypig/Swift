from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from swiftproxy.models import RankedConfig, TestResult
from swiftproxy.protocols.parser import SUPPORTED_PROXY_SCHEMES, parse_uri
from swiftproxy.protocols.serialization import serialize_uri
from swiftproxy.storage import atomic_write

HAPP_PROTOCOLS = {"vless", "vmess", "trojan", "ss", "hysteria2"}


def extract_country_from_remark(remark: str | None) -> str | None:
    if not remark:
        return None
    for match in re.finditer(r"[\U0001F1E6-\U0001F1FF]{2}", remark):
        chars = match.group(0)
        c = "".join(chr(ord(ch) - 127397) for ch in chars)
        if len(c) == 2 and c.isalpha():
            return c.upper()
    for word in re.findall(r"\b[A-Z]{2}\b", remark):
        if word not in ("VL", "VM", "TR", "SS", "HY", "BL", "OK", "TG", "IP", "BS"):
            return word
    return None


def display_name(
    result: TestResult,
    index: int,
    prefix: str,
) -> str:
    country = (result.country or "??").upper()
    flag = "🏴‍☠️"
    if len(country) == 2 and country.isalpha() and country != "??":
        flag = "".join(chr(ord(character) + 127397) for character in country)
    return f"{flag} {country} · {prefix}{index:03d}"


def subscription_lines(items: Iterable[RankedConfig], prefix: str) -> list[str]:
    lines = []
    for index, item in enumerate(items, 1):
        name = display_name(item.result, index, prefix)
        lines.append(serialize_uri(item.config, name))
    return lines


def country_ordered(items: Iterable[RankedConfig]) -> list[RankedConfig]:
    return sorted(
        items,
        key=lambda item: (
            (item.result.country or "ZZ").upper(),
            -item.score,
            item.config.fingerprint,
        ),
    )


def happ_subscription(lines: list[str], title: str, repository: str) -> str:
    metadata = [
        f"#profile-title: {title}",
        "#profile-update-interval: 1",
        f"#profile-web-page-url: {repository}",
    ]
    return "\n".join([*metadata, *lines]) + "\n"


def plain_subscription(lines: list[str]) -> str:
    return "\n".join(lines) + ("\n" if lines else "")


def validated_proxy_lines(lines: Iterable[str], label: str) -> list[str]:
    validated: list[str] = []
    fingerprints: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        scheme = line.partition(":")[0].lower()
        if scheme not in SUPPORTED_PROXY_SCHEMES:
            raise RuntimeError(f"{label} contains a non-proxy URL")
        try:
            config = parse_uri(line)
        except ValueError as exc:
            raise RuntimeError(f"{label} contains an invalid proxy URI") from exc
        if config.fingerprint in fingerprints:
            raise RuntimeError(f"{label} contains duplicates")
        fingerprints.add(config.fingerprint)
        validated.append(line)
    return validated


def write_final_subscriptions(
    root: Path,
    main_lines: Iterable[str],
    white_lines: Iterable[str],
    repository: str,
) -> None:
    main = validated_proxy_lines(main_lines, "final Main subscription")
    white = validated_proxy_lines(white_lines, "final White subscription")
    happ_main = [line for line in main if parse_uri(line).protocol in HAPP_PROTOCOLS]
    happ_white = [line for line in white if parse_uri(line).protocol in HAPP_PROTOCOLS]
    outputs = {
        root / "sub/main.txt": plain_subscription(main),
        root / "sub/white.txt": plain_subscription(white),
        root / "sub/happ/main.txt": happ_subscription(happ_main, "Swift Main", repository),
        root / "sub/happ/white.txt": happ_subscription(happ_white, "Swift White", repository),
    }

    previous = {path: path.read_text() if path.exists() else None for path in outputs}
    try:
        for path, content in outputs.items():
            atomic_write(path, content)
    except BaseException:
        for path, content in previous.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, content)
        raise


def check_outputs(root: Path, main_limit: int, white_limit: int) -> None:
    for relative, limit in (("sub/main.txt", main_limit), ("sub/white.txt", white_limit)):
        lines = validated_proxy_lines((root / relative).read_text().splitlines(), relative)
        if len(lines) > limit:
            raise RuntimeError(f"{relative} exceeds its limit")
    validated_proxy_lines((root / "sub/all.txt").read_text().splitlines(), "sub/all.txt")
    for relative in ("sub/happ/main.txt", "sub/happ/white.txt"):
        lines = [
            line.strip() for line in (root / relative).read_text().splitlines() if line.strip()
        ]
        if not lines or not lines[0].startswith("#profile-title: Swift"):
            raise RuntimeError(f"{relative} has no Swift metadata")
        proxy_lines = validated_proxy_lines(lines, relative)
        for line in proxy_lines:
            if parse_uri(line).protocol not in HAPP_PROTOCOLS:
                raise RuntimeError(f"{relative} contains a protocol Happ does not document")

        lane = "main" if relative.endswith("main.txt") else "white"
        universal = validated_proxy_lines(
            (root / f"sub/{lane}.txt").read_text().splitlines(),
            f"sub/{lane}.txt",
        )
        expected = [
            parse_uri(line).fingerprint
            for line in universal
            if parse_uri(line).protocol in HAPP_PROTOCOLS
        ]
        actual = [parse_uri(line).fingerprint for line in proxy_lines]
        if actual != expected:
            raise RuntimeError(f"{relative} does not match the compatible {lane} population")
    stats = json.loads((root / "stats.json").read_text())
    if (
        stats.get("project") != "Swift"
        or stats.get("tagline") != "Filter the garbage. Keep what works."
    ):
        raise RuntimeError("stats.json branding is invalid")

    main_lines = [
        line
        for line in (root / "sub/main.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    white_lines = [
        line
        for line in (root / "sub/white.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    prod_stats = stats.get("production", {})
    if prod_stats.get("main") is not None and len(main_lines) != prod_stats["main"]:
        raise RuntimeError(
            f"sub/main.txt count ({len(main_lines)}) != stats.production.main ({prod_stats['main']})"
        )
    if prod_stats.get("white") is not None and len(white_lines) != prod_stats["white"]:
        raise RuntimeError(
            f"sub/white.txt count ({len(white_lines)}) != stats.production.white ({prod_stats['white']})"
        )
