from __future__ import annotations

import hashlib
import html
import logging
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from mtproxy_checker.parser import decode_secret

from .models import SourceSpec
from .parsing import validate_host

LOGGER = logging.getLogger("swift.telegram")
URL_RE = re.compile(r"(?i)(?:https?://t\.me/proxy|tg://proxy)\?[^\s<>\"']+")


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


def empty_history() -> dict[str, Any]:
    return {"version": 1, "proxies": {}}


def _query(url: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in urlsplit(url).query.split("&"):
        if not part:
            continue
        key, separator, value = part.partition("=")
        key = unquote(key).lower()
        if not separator or key in result:
            raise ValueError("MALFORMED_URL")
        result[key] = unquote(value)
    return result


def _canonical_secret(value: str) -> tuple[str, str]:
    if not value or len(value) > 1024 or any(ord(character) < 33 for character in value):
        raise ValueError("MALFORMED_SECRET")
    try:
        parsed = decode_secret(value)
    except Exception as exc:
        raise ValueError("MALFORMED_SECRET") from exc
    kind = parsed.kind.value
    if kind == "extended-raw":
        raise ValueError("UNSUPPORTED_SECRET")
    if parsed.is_faketls:
        domain = parsed.faketls_domain.lower().rstrip(".")
        try:
            validate_host(domain)
            domain = domain.encode("idna").decode("ascii")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("MALFORMED_SECRET") from exc
        return f"ee{parsed.raw_secret.hex()}{domain.encode().hex()}", "faketls"
    if kind == "dd-secure":
        return f"dd{parsed.raw_secret.hex()}", "secure"
    return parsed.raw_secret.hex(), "raw"


def parse_proxy_url(url: str) -> TelegramProxy:
    url = html.unescape(url.strip()).rstrip(".,;)")
    if len(url) > 2048:
        raise ValueError("MALFORMED_URL")
    parts = urlsplit(url)
    is_tg = parts.scheme.lower() == "tg" and parts.netloc.lower() == "proxy"
    is_web = (
        parts.scheme.lower() in {"http", "https"}
        and (parts.hostname or "").lower() == "t.me"
        and parts.path.rstrip("/").lower() == "/proxy"
    )
    if not is_tg and not is_web:
        raise ValueError("MALFORMED_URL")
    query = _query(url)
    try:
        host = query["server"].strip().removeprefix("[").removesuffix("]").lower().rstrip(".")
        port = int(query["port"])
        secret, secret_kind = _canonical_secret(query["secret"])
    except KeyError as exc:
        raise ValueError("MALFORMED_URL") from exc
    except ValueError as exc:
        if str(exc) in {"MALFORMED_SECRET", "UNSUPPORTED_SECRET"}:
            raise
        raise ValueError("INVALID_PORT") from exc
    if not 1 <= port <= 65535:
        raise ValueError("INVALID_PORT")
    try:
        validate_host(host)
        host = host.encode("idna").decode("ascii")
    except ValueError as exc:
        reason = "PRIVATE_ENDPOINT" if "private" in str(exc) else "INVALID_ENDPOINT"
        raise ValueError(reason) from exc
    except UnicodeError as exc:
        raise ValueError("INVALID_ENDPOINT") from exc
    return TelegramProxy(host, port, secret, secret_kind)


def extract_proxy_urls(text: str) -> list[str]:
    return [match.group(0) for match in URL_RE.finditer(html.unescape(text))]


def deduplicate(proxies: list[TelegramProxy]) -> tuple[list[TelegramProxy], int]:
    unique: dict[str, TelegramProxy] = {}
    duplicates = 0
    for proxy in proxies:
        existing = unique.get(proxy.fingerprint)
        if existing is None:
            unique[proxy.fingerprint] = proxy
        else:
            existing.sources.update(proxy.sources)
            duplicates += 1
    return sorted(unique.values(), key=lambda item: item.fingerprint), duplicates


def telegram_source_specs(settings: dict[str, Any]) -> list[SourceSpec]:
    return [
        SourceSpec(item["id"], item["name"], item["url"], {"telegram"})
        for item in settings["telegram"].get("sources", [])
    ]


def parse_source_results(
    results: list[Any],
) -> tuple[list[TelegramProxy], Counter[str], dict[str, Any]]:
    proxies: list[TelegramProxy] = []
    failures: Counter[str] = Counter()
    source_stats: dict[str, Any] = {}
    for result in results:
        source_id = result.source.source_id
        if result.error:
            source_stats[source_id] = {
                "status": result.error,
                "fetched": 0,
                "unique": 0,
                "working": 0,
            }
            continue
        urls = extract_proxy_urls(result.content)
        seen: set[str] = set()
        for url in urls:
            try:
                proxy = parse_proxy_url(url)
            except ValueError as exc:
                failures[str(exc)] += 1
                continue
            proxy.sources.add(result.source.name)
            proxies.append(proxy)
            seen.add(proxy.fingerprint)
        source_stats[source_id] = {
            "status": "OK" if urls else "EMPTY",
            "fetched": len(urls),
            "unique": len(seen),
            "working": 0,
        }
    return proxies, failures, source_stats


def previous_output_proxies(root: Path) -> list[TelegramProxy]:
    proxies: list[TelegramProxy] = []
    for name in ("all.txt", "stable.txt", "fastest.txt"):
        path = root / "Telegram" / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                proxy = parse_proxy_url(line)
            except ValueError:
                continue
            proxy.sources.add("previous-output")
            proxies.append(proxy)
    return proxies


def choose_candidates(
    proxies: list[TelegramProxy], history: dict[str, Any], limit: int, seed: str
) -> list[TelegramProxy]:
    records = history.get("proxies", {})

    def key(proxy: TelegramProxy) -> tuple[int, float, str]:
        record = records.get(proxy.fingerprint, {})
        state = record.get("state", "new")
        if state == "active":
            tier = 0
        elif state == "degraded":
            tier = 1
        elif float(record.get("score", 0)) >= 65:
            tier = 2
        elif not record:
            tier = 3
        else:
            tier = 4
        lottery = hashlib.sha256(f"{seed}:{proxy.fingerprint}".encode()).hexdigest()
        return tier, -float(record.get("score", 0)), lottery

    return sorted(proxies, key=key)[:limit]


def _availability(observation: dict[str, Any]) -> float:
    attempts = int(observation.get("attempts", 0))
    return int(observation.get("successes", 0)) / attempts if attempts else 0.0


def _is_strong(observation: dict[str, Any]) -> bool:
    return _availability(observation) >= 2 / 3


def _failure_streak(observations: list[dict[str, Any]]) -> int:
    failures = 0
    for observation in reversed(observations):
        if _is_strong(observation):
            break
        failures += 1
    return failures


def _success_streak(observations: list[dict[str, Any]]) -> int:
    successes = 0
    for observation in reversed(observations):
        if not _is_strong(observation):
            break
        successes += 1
    return successes


def state_after(
    previous: str,
    observations: list[dict[str, Any]],
    promotion_runs: int,
    remove_failures: int,
) -> str:
    if observations and _is_strong(observations[-1]):
        if previous in {"active", "degraded"} or _success_streak(observations) >= promotion_runs:
            return "active"
        return "new"
    failures = _failure_streak(observations)
    if previous in {"active", "degraded"} and failures < remove_failures:
        return "degraded"
    if failures >= remove_failures:
        return "dead"
    return "new"


def add_observation(
    history: dict[str, Any],
    proxy: TelegramProxy,
    result: TelegramResult,
    settings: dict[str, Any],
) -> dict[str, Any]:
    records = history.setdefault("proxies", {})
    record = records.setdefault(
        proxy.fingerprint,
        {"sources": [], "secret_kind": proxy.secret_kind, "observations": []},
    )
    record["sources"] = sorted(proxy.sources - {"previous-output"})
    record["secret_kind"] = proxy.secret_kind
    record["last_seen"] = result.timestamp
    observations = record.setdefault("observations", [])
    observations.append(result.observation(bool(proxy.sources - {"previous-output"})))
    record["observations"] = observations[-int(settings["window"]) :]
    record["state"] = state_after(
        str(record.get("state", "new")),
        record["observations"],
        int(settings["promotion_runs"]),
        int(settings["remove_failures"]),
    )
    return record


def _linear(value: float | None, good: float, bad: float) -> float:
    if value is None:
        return 0.0
    if value <= good:
        return 1.0
    if value >= bad:
        return 0.0
    return 1 - (value - good) / (bad - good)


def score_proxy(record: dict[str, Any], secret_kind: str) -> tuple[float, float]:
    observations = record.get("observations", [])
    if not observations:
        return 0.0, 0.0
    weighted = 0.0
    total_weight = 0.0
    for age, observation in enumerate(reversed(observations)):
        weight = 0.88**age
        weighted += _availability(observation) * weight
        total_weight += weight
    availability = weighted / total_weight
    recent = sum(_availability(item) for item in observations[-3:]) / min(3, len(observations))
    metrics = next((item for item in reversed(observations) if _is_strong(item)), {})
    median = _linear(metrics.get("median_rtt"), 120, 2500)
    p95 = _linear(metrics.get("p95_rtt"), 180, 4000)
    jitter = _linear(metrics.get("jitter"), 30, 1500)
    useful = {"faketls": 1.0, "secure": 0.8, "raw": 0.6}.get(secret_kind, 0.0)
    fresh = 1.0 if observations[-1].get("fresh_source") else 0.0
    score = 100 * (
        0.45 * availability
        + 0.18 * median
        + 0.08 * p95
        + 0.07 * jitter
        + 0.12 * recent
        + 0.05 * useful
        + 0.05 * fresh
    )
    return round(score, 2), availability


def rank_proxies(
    proxies: list[TelegramProxy],
    results: dict[str, TelegramResult],
    history: dict[str, Any],
    previous_order: list[str],
) -> tuple[list[RankedTelegram], list[RankedTelegram]]:
    previous_index = {fingerprint: index for index, fingerprint in enumerate(previous_order)}
    working: list[RankedTelegram] = []
    stable: list[RankedTelegram] = []
    records = history.get("proxies", {})
    for proxy in proxies:
        result = results.get(proxy.fingerprint)
        if result is None:
            continue
        record = records.get(proxy.fingerprint, {})
        previous_score = float(record.get("score", 0))
        score, availability = score_proxy(record, proxy.secret_kind)
        if record.get("state") == "degraded":
            score = max(score, previous_score - 6)
        record["score"] = score
        ranked = RankedTelegram(proxy, result, score, str(record.get("state", "new")), availability)
        if result.working:
            working.append(ranked)
        if ranked.state in {"active", "degraded"}:
            stable.append(ranked)

    def quality_key(item: RankedTelegram) -> tuple[int, int, str]:
        return (
            -math.floor(item.score),
            previous_index.get(item.proxy.fingerprint, 1_000_000),
            item.proxy.fingerprint,
        )

    working.sort(key=quality_key)
    stable.sort(key=quality_key)
    return working, stable


def fastest_proxies(working: list[RankedTelegram], limit: int) -> list[RankedTelegram]:
    def key(item: RankedTelegram) -> tuple[float, float, str]:
        median = item.result.median_rtt or 1e9
        tail = max(0.0, (item.result.p95_rtt or median) - median)
        jitter = item.result.jitter or 0.0
        health_penalty = (1 - item.result.success_ratio) * 800
        return (
            median + 0.25 * tail + 0.5 * jitter + health_penalty,
            -item.score,
            item.proxy.fingerprint,
        )

    return sorted(working, key=key)[:limit]


def select_message_targets(
    working: list[RankedTelegram],
    stable: list[RankedTelegram],
    fastest: list[RankedTelegram],
    rotation_slot: int = 0,
) -> dict[str, Any]:
    selected: list[tuple[str, RankedTelegram]] = []

    def suitable(candidates: list[RankedTelegram]) -> list[RankedTelegram]:
        healthy = [
            item
            for item in candidates
            if item.result.attempts >= 3
            and item.result.successes == item.result.attempts
            and (item.result.median_rtt or math.inf) <= 1500
            and (item.result.p95_rtt or math.inf) <= 2500
            and (item.result.jitter or math.inf) <= 700
        ]
        preferred = [
            item
            for item in healthy
            if item.proxy.port == 443 and item.proxy.secret_kind == "faketls"
        ]
        if preferred:
            return preferred
        standard_port = [item for item in healthy if item.proxy.port == 443]
        return standard_port or healthy

    def add(label: str, candidates: list[RankedTelegram], offset: int) -> None:
        used = {item.proxy.fingerprint for _, item in selected}
        candidates = suitable(candidates)
        rotating = candidates[: min(3, len(candidates))]
        if rotating:
            start = (rotation_slot + offset) % len(rotating)
            candidates = rotating[start:] + rotating[:start] + candidates[len(rotating) :]
        choice = next((item for item in candidates if item.proxy.fingerprint not in used), None)
        if choice is not None:
            selected.append((label, choice))

    current_stable = [item for item in stable if item.result.working and item.state == "active"]
    add("fastest", fastest, 0)
    add("stable", current_stable or working, 1)
    add(
        "backup",
        [item for item in working if item.proxy.host not in {x.proxy.host for _, x in selected}],
        2,
    )
    if len(selected) < 3:
        add("backup", working, 2)
    return {
        label: {
            "url": item.proxy.url,
            "score": item.score,
            "median_rtt_ms": item.result.median_rtt,
        }
        for label, item in selected[:3]
    }


def assess_run(
    previous: dict[str, Any] | None,
    *,
    successful_sources: int,
    expected: int,
    completed: int,
    working: int,
    control_ok: bool,
    collapse_ratio: float,
    hold_runs: int,
) -> tuple[bool, str | None, int]:
    previous_streak = int((previous or {}).get("suspicious_streak", 0))
    if successful_sources == 0:
        return False, "ALL_SOURCES_FAILED", previous_streak
    if expected and completed < expected * 0.8:
        return False, "GLOBAL_TIMEOUT", previous_streak
    production = (previous or {}).get("production", {})
    previous_working = int(production.get("working", (previous or {}).get("working", 0)))
    threshold = max(1, math.floor(previous_working * collapse_ratio))
    collapsed = working < threshold
    if not collapsed:
        return True, None, 0
    if not control_ok:
        return False, "TELEGRAM_CONTROL_FAILED", previous_streak
    streak = previous_streak + 1
    if streak <= hold_runs:
        return False, "MASS_FAILURE", streak
    return True, None, 0


def prune_history(history: dict[str, Any], now: datetime | None = None) -> None:
    cutoff = (now or datetime.now(UTC)) - timedelta(days=14)
    records = history.get("proxies", {})
    for fingerprint, record in list(records.items()):
        try:
            last_seen = datetime.fromisoformat(str(record["last_seen"]))
        except (KeyError, ValueError):
            del records[fingerprint]
            continue
        if last_seen < cutoff and record.get("state") != "active":
            del records[fingerprint]
