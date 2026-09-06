from __future__ import annotations

import hashlib
import math
import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote


@dataclass(slots=True)
class TelegramProxy:
    host: str
    port: int
    secret: str
    secret_kind: str
    sources: set[str] = field(default_factory=set)
    resolved_ip: str | None = None

    @property
    def fingerprint(self) -> str:
        identity = f"{self.host}\0{self.port}\0{self.secret}".encode()
        return hashlib.sha256(identity).hexdigest()

    @property
    def url(self) -> str:
        host = quote(self.host, safe=".-_:")
        return f"https://t.me/proxy?server={host}&port={self.port}&secret={self.secret}"


@dataclass(slots=True)
class TelegramResult:
    fingerprint: str
    timestamp: str
    attempts: int = 0
    successes: int = 0
    rtts_ms: list[float] = field(default_factory=list)
    reason: str | None = None

    @property
    def success_ratio(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0

    @property
    def working(self) -> bool:
        return self.attempts > 0 and self.successes >= math.ceil(self.attempts * 2 / 3)

    @property
    def median_rtt(self) -> float | None:
        return statistics.median(self.rtts_ms) if self.rtts_ms else None

    @property
    def p95_rtt(self) -> float | None:
        if not self.rtts_ms:
            return None
        ordered = sorted(self.rtts_ms)
        return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]

    @property
    def jitter(self) -> float | None:
        return statistics.pstdev(self.rtts_ms) if len(self.rtts_ms) > 1 else 0.0

    def observation(self, fresh: bool) -> dict[str, Any]:
        value: dict[str, Any] = {
            "timestamp": self.timestamp,
            "attempts": self.attempts,
            "successes": self.successes,
            "success_ratio": round(self.success_ratio, 3),
            "fresh_source": fresh,
        }
        for key, item in (
            ("median_rtt", self.median_rtt),
            ("p95_rtt", self.p95_rtt),
            ("jitter", self.jitter),
            ("reason", self.reason),
        ):
            if item is not None:
                value[key] = round(item, 2) if isinstance(item, float) else item
        return value


@dataclass(slots=True)
class RankedTelegram:
    proxy: TelegramProxy
    result: TelegramResult
    score: float
    state: str
    availability: float


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
