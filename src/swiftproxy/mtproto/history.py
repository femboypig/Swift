from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from swiftproxy.mtproto.models import TelegramProxy, TelegramResult


def empty_history() -> dict[str, Any]:
    return {"version": 1, "proxies": {}}


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
