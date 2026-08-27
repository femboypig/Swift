from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ProxyConfig:
    protocol: str
    host: str
    port: int
    auth: dict[str, str | int]
    options: dict[str, Any] = field(default_factory=dict)
    remark: str = ""
    sources: set[str] = field(default_factory=set)
    lanes: set[str] = field(default_factory=set)
    resolved_ip: str | None = None

    @property
    def fingerprint(self) -> str:
        value = {
            "protocol": self.protocol,
            "host": self.host.lower().rstrip("."),
            "port": self.port,
            "auth": self.auth,
            "options": self.options,
        }
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def endpoint(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def label(self) -> str:
        if self.protocol == "vless" and self.options.get("security") == "reality":
            return "Reality"
        return {
            "vless": "VLESS",
            "vmess": "VMess",
            "trojan": "Trojan",
            "ss": "SS",
            "hysteria2": "HY2",
            "tuic": "TUIC",
        }[self.protocol]


@dataclass(slots=True)
class SourceSpec:
    source_id: str
    name: str
    url: str
    lanes: set[str]
    content_type: str = "auto"


@dataclass(slots=True)
class SourceResult:
    source: SourceSpec
    content: str = ""
    error: str | None = None
    status: int | None = None
    elapsed_ms: int | None = None


@dataclass(slots=True)
class TestResult:
    fingerprint: str
    lane: str
    timestamp: str
    success_count: int = 0
    failure_count: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    connect_times_ms: list[float] = field(default_factory=list)
    response_times_ms: list[float] = field(default_factory=list)
    median_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    min_latency_ms: float | None = None
    max_latency_ms: float | None = None
    jitter_ms: float | None = None
    median_connect_ms: float | None = None
    median_response_ms: float | None = None
    throughput_bps: float | None = None
    country: str | None = None
    asn: int | None = None
    provider: str | None = None
    reason: str | None = None

    @property
    def worked(self) -> bool:
        return self.success_count > 0

    @property
    def success_ratio(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total else 0.0

    def observation(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "timestamp": self.timestamp,
            "success": self.worked,
            "success_ratio": round(self.success_ratio, 3),
        }
        optional = {
            "median_latency": self.median_latency_ms,
            "p95_latency": self.p95_latency_ms,
            "jitter": self.jitter_ms,
            "throughput": self.throughput_bps,
            "country": self.country,
            "asn": self.asn,
            "provider": self.provider,
            "reason": self.reason,
        }
        for key, item in optional.items():
            if item is not None:
                value[key] = round(item, 2) if isinstance(item, float) else item
        return value


@dataclass(slots=True)
class RankedConfig:
    config: ProxyConfig
    lane: str
    result: TestResult
    score: float
    state: str
    availability: float
