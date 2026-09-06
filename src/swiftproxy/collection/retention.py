from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from swiftproxy.models import ProxyConfig
from swiftproxy.protocols.parser import parse_uri

LOGGER = logging.getLogger(__name__)


def previous_subscription_configs(
    root: Path,
    history: dict[str, Any],
    allowed_sources: dict[str, set[str]] | None = None,
) -> list[ProxyConfig]:
    configs: list[ProxyConfig] = []
    rejected = 0
    records = history.get("configs", {})
    for lane in ("main", "white"):
        path = root / f"sub/{lane}.txt"
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                config = parse_uri(line)
            except ValueError:
                rejected += 1
                continue
            record = records.get(config.fingerprint, {})
            sources = set(record.get("sources", ["previous-output"]))
            if allowed_sources is not None and sources.isdisjoint(allowed_sources[lane]):
                continue
            config.sources.update(sources)
            config.lanes.add(lane)
            configs.append(config)
    if rejected:
        LOGGER.warning("PREVIOUS_PARSE_ERROR count=%d", rejected)
    return configs
