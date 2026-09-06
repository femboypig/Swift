from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from swiftproxy.mtproto.models import RankedTelegram
from swiftproxy.mtproto.parsing import parse_proxy_url
from swiftproxy.storage import atomic_write


def previous_order(root: Path, name: str) -> list[str]:
    path = root / "Telegram" / name
    if not path.exists():
        return []
    order: list[str] = []
    for line in path.read_text().splitlines():
        try:
            order.append(parse_proxy_url(line).fingerprint)
        except ValueError:
            continue
    return order


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(bool(line.strip()) for line in path.read_text().splitlines())


def write_proxy_file(path: Path, items: list[RankedTelegram]) -> None:
    content = "\n".join(item.proxy.url for item in items)
    atomic_write(path, content + ("\n" if content else ""))


def validate_outputs(root: Path, settings: dict[str, Any]) -> None:
    limits = settings["telegram"]["limits"]
    for name, limit in (
        ("all.txt", None),
        ("stable.txt", int(limits["stable"])),
        ("fastest.txt", int(limits["fastest"])),
    ):
        path = root / "Telegram" / name
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        if limit is not None and len(lines) > limit:
            raise RuntimeError(f"Telegram/{name} exceeds its limit")
        fingerprints = [parse_proxy_url(line).fingerprint for line in lines]
        if len(fingerprints) != len(set(fingerprints)):
            raise RuntimeError(f"Telegram/{name} contains duplicates")
    status = json.loads((root / "Telegram/status.json").read_text())
    if status.get("project") != "Swift":
        raise RuntimeError("Telegram/status.json branding is invalid")
