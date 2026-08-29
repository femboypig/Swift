from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

LOGGER = logging.getLogger("swift")


def probe_ru_targets(
    targets: list[dict[str, Any]],
    check_type: str = "tcp_tls",
    probe_url: str | None = None,
    probe_key: str | None = None,
    timeout: float = 12.0,
) -> dict[str, dict[str, Any]]:
    url = probe_url or os.environ.get("SWIFT_RU_PROBE_URL")
    key = probe_key or os.environ.get("SWIFT_RU_PROBE_KEY", "")

    if not url or not targets:
        return {}

    payload = json.dumps({"type": check_type, "targets": targets}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Swift-Proxy-Filter/1.0",
    }
    if key:
        headers["X-Swift-Key"] = key

    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                LOGGER.warning("RU_PROBE_HTTP_ERROR status=%d", response.status)
                return {}
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        LOGGER.warning("RU_PROBE_FAILED error=%s", exc)
        return {}

    results_map: dict[str, dict[str, Any]] = {}
    for item in data.get("results", []):
        target_info = item.get("target", {})
        host = target_info.get("host")
        port = target_info.get("port")
        if host and port is not None:
            key_id = f"{host}:{port}"
            results_map[key_id] = {
                "ok": bool(item.get("ok")),
                "latency_ms": item.get("latency_ms"),
                "error": item.get("error"),
            }
    LOGGER.info(
        "ru_probe type=%s sent=%d responded=%d passed=%d",
        check_type,
        len(targets),
        len(results_map),
        sum(r["ok"] for r in results_map.values()),
    )
    return results_map
