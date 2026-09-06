from __future__ import annotations

import asyncio
import contextlib
import math
import time
from collections.abc import Awaitable, Callable
from typing import Any

from swiftproxy.verification.control import _direct_control


class DownloadGovernor:
    def __init__(self, concurrency: int, budget_bps: int, interface: str, baseline_ms: float):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.budget_bps = budget_bps
        self.per_transfer_bps = budget_bps // concurrency
        self.interface = interface
        self.baseline_ms = baseline_ms
        self.bytes = 0
        self.active = 0
        self.peak = 0

    async def control(self, factor: float, floor_ms: float) -> dict[str, Any]:
        result = await _direct_control(self.interface)
        limit = max(floor_ms, self.baseline_ms * factor)
        result["congested"] = not result["success"] or (result["latency_ms"] or math.inf) > limit
        return result

    @contextlib.asynccontextmanager
    async def slot(self):
        async with self.semaphore:
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                yield
            finally:
                self.active -= 1


class StageLimiter:
    def __init__(self, limit: int):
        self.semaphore = asyncio.Semaphore(limit)
        self.active = 0
        self.peak = 0
        self.total_ms = 0.0

    @contextlib.asynccontextmanager
    async def slot(self):
        async with self.semaphore:
            started = time.monotonic()
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                yield
            finally:
                self.active -= 1
                self.total_ms += (time.monotonic() - started) * 1000

    def summary(self) -> dict[str, Any]:
        return {"peak_active": self.peak, "total_candidate_ms": round(self.total_ms, 2)}


async def _run_admitted(
    admission: asyncio.Semaphore,
    operation: Callable[[], Awaitable[dict[str, Any]]],
    timeout: float,
) -> dict[str, Any]:
    async with admission:
        return await asyncio.wait_for(operation(), timeout)
