from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from swiftproxy.verification.control import _core_control, _direct_control
from swiftproxy.verification.preflight import _physical_preflight

LOGGER = logging.getLogger(__name__)


async def _bounded_preflight(interface: str, timeout: float) -> Any | None:
    try:
        return await asyncio.wait_for(_physical_preflight(interface), timeout)
    except TimeoutError:
        return None


@dataclass(slots=True)
class PathHealth:
    preflight: Any | None
    control: dict[str, Any]
    core_control: dict[str, Any]

    @property
    def healthy(self) -> bool:
        return bool(
            self.preflight is not None
            and self.preflight.ok
            and self.control.get("success")
            and self.core_control.get("success")
        )

    def record(self, attempt: int) -> dict[str, Any]:
        preflight = self.preflight
        return {
            "attempt": attempt,
            "healthy": self.healthy,
            "preflight": (
                {
                    "ok": bool(preflight.ok),
                    "dns_ok": bool(preflight.dns_ok),
                    "https_passed": int(preflight.https_passed),
                    "https_total": int(preflight.https_total),
                    "download_ok": bool(preflight.download_ok),
                    "diagnostics": preflight.diagnostics,
                }
                if preflight is not None
                else {"ok": False, "reason": "PREFLIGHT_TIMEOUT"}
            ),
            "control": {
                "success": bool(self.control.get("success")),
                "path_mode": self.control.get("path_mode"),
            },
            "core_control": {
                "success": bool(self.core_control.get("success")),
                "category": self.core_control.get("category"),
            },
        }


async def _path_health_once(interface: str, core: str, timeout: float) -> PathHealth:
    preflight = await _bounded_preflight(interface, timeout)
    control = await _direct_control(interface)
    core_control = await _core_control(core, interface)
    return PathHealth(preflight, control, core_control)


async def _wait_for_healthy_path(
    interface: str,
    core: str,
    timeout: float,
    attempts: int,
    delay: float,
    confirmations: int,
    phase: str,
) -> tuple[PathHealth, list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    consecutive = 0
    saw_failure = False
    last: PathHealth | None = None
    for attempt in range(1, attempts + 1):
        last = await _path_health_once(interface, core, timeout)
        record = last.record(attempt)
        records.append(record)
        if last.healthy:
            consecutive += 1
            required = confirmations if saw_failure else 1
            LOGGER.info(
                "RU %s path check attempt=%d/%d PASS confirmation=%d/%d",
                phase,
                attempt,
                attempts,
                consecutive,
                required,
            )
            if consecutive >= required:
                return last, records
        else:
            saw_failure = True
            consecutive = 0
            LOGGER.warning(
                "RU %s path check attempt=%d/%d FAIL preflight=%s control=%s core=%s",
                phase,
                attempt,
                attempts,
                record["preflight"],
                record["control"],
                record["core_control"],
            )
        if attempt < attempts:
            await asyncio.sleep(delay)
    assert last is not None
    return last, records
