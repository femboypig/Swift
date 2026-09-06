from __future__ import annotations

import math
import time
from datetime import UTC, datetime
from typing import Any

from swiftproxy.verification.constants import MIN_THROUGHPUT_KBPS, TERMINAL_PASS


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _terminal(record: dict[str, Any], reason: str, passed: bool = False) -> dict[str, Any]:
    record["final"] = {
        "terminal_state": TERMINAL_PASS if passed else "FAIL",
        "reason": reason,
        "passed": passed,
        "accounted_for": True,
    }
    record["total_duration_ms"] = round((time.monotonic() - record.pop("_started")) * 1000, 2)
    return record


def download_failure_reason(
    attempt: dict[str, Any], round_name: str, *, check_speed: bool = True
) -> str | None:
    if not attempt["success"]:
        return (
            "STALLED" if attempt.get("category") == "STALLED" else f"DOWNLOAD_{round_name}_FAILED"
        )
    if check_speed and float(attempt.get("speed_kbps", 0)) < MIN_THROUGHPUT_KBPS:
        return "TOO_SLOW"
    return None


def _apply_freshness(result: dict[str, Any], freshness: dict[str, Any]) -> None:
    result["freshness"] = freshness
    if freshness["passed"]:
        return
    result["final"] = {
        "terminal_state": "FAIL",
        "reason": "FRESHNESS_FAILED",
        "passed": False,
        "accounted_for": True,
    }


def _hold_population_collapse(
    previous_pass: int,
    current_pass: int,
    finalization_checks: list[dict[str, Any]],
) -> bool:
    if previous_pass < 20:
        return False
    collapsed = current_pass < max(3, math.ceil(previous_pass * 0.10))
    finalization_was_unstable = any(
        not check.get("healthy", False) for check in finalization_checks
    )
    return collapsed and finalization_was_unstable
