from __future__ import annotations

import json
import logging
import math
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

LOGGER = logging.getLogger("swift")


def _send_probe_chunk(
    targets: list[dict[str, Any]],
    check_type: str,
    url: str,
    key: str,
    timeout: float,
) -> dict[str, dict[str, Any]]:
    if urlsplit(url).scheme != "https":
        LOGGER.warning("RU_PROBE_REQUIRES_HTTPS")
        return {}
    payload = json.dumps({"type": check_type, "targets": targets}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Swift-Proxy-Filter/1.0",
    }
    headers["X-Swift-Key"] = key

    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                LOGGER.warning("RU_PROBE_HTTP_ERROR status=%d", response.status)
                return {}
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                return {}
            data = json.loads(body)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        LOGGER.warning("RU_PROBE_FAILED error=%s", exc)
        return {}

    control = data.get("control") if isinstance(data, dict) else None
    has_ok_result = any(item.get("ok") for item in data.get("results", [])) if isinstance(data.get("results"), list) else False
    if not isinstance(control, dict) or (control.get("telegram_ok") is not True and not has_ok_result):
        LOGGER.warning("RU_PROBE_CONTROL_UNPROVEN")
        return {}
    expected = {target["id"]: target for target in targets}
    chunk_map: dict[str, dict[str, Any]] = {}
    try:
        for item in data["results"]:
            target_info = item["target"]
            key_id = target_info["id"]
            target = expected[key_id]
            if key_id in chunk_map or (target_info["host"], target_info["port"]) != (
                target["host"],
                target["port"],
            ):
                raise ValueError("invalid probe accounting")
            if type(item["ok"]) is not bool:
                raise ValueError("invalid probe status")
            latency = item.get("latency_ms")
            if item["ok"] and (
                not isinstance(latency, (int, float)) or not math.isfinite(latency) or latency <= 0
            ):
                raise ValueError("invalid probe latency")
            chunk_map[key_id] = {
                "ok": item["ok"],
                "latency_ms": latency,
                "error": item.get("error"),
            }
    except (KeyError, TypeError, ValueError):
        LOGGER.warning("RU_PROBE_INVALID_RESPONSE")
        return {}
    return chunk_map


def probe_ru_targets(
    targets: list[dict[str, Any]],
    check_type: str = "mtproto",
    probe_url: str | None = None,
    probe_key: str | None = None,
    timeout: float = 45.0,
    chunk_size: int = 25,
    request_concurrency: int = 1,
) -> dict[str, dict[str, Any]]:
    url = os.environ.get("SWIFT_RU_PROBE_URL", "") if probe_url is None else probe_url
    key = os.environ.get("SWIFT_RU_PROBE_KEY", "") if probe_key is None else probe_key

    if not url or not key or not targets:
        if url and not key:
            LOGGER.warning("RU_PROBE_KEY_MISSING")
        return {}
    identifiers = [item.get("id") for item in targets if isinstance(item, dict)]
    if len(identifiers) != len(targets) or any(
        not isinstance(identifier, str) or not identifier for identifier in identifiers
    ) or len(set(identifiers)) != len(identifiers):
        LOGGER.warning("RU_PROBE_INVALID_TARGET_IDENTIFIERS")
        return {}

    chunks = [
        targets[start : start + max(1, chunk_size)]
        for start in range(0, len(targets), max(1, chunk_size))
    ]
    with ThreadPoolExecutor(max_workers=max(1, request_concurrency)) as executor:
        responses = executor.map(
            lambda chunk: _send_probe_chunk(chunk, check_type, url, key, timeout), chunks
        )
        results_map = {
            result_key: value for response in responses for result_key, value in response.items()
        }

    LOGGER.info(
        "ru_probe type=%s sent=%d responded=%d passed=%d",
        check_type,
        len(targets),
        len(results_map),
        sum(r["ok"] for r in results_map.values()),
    )
    return results_map
