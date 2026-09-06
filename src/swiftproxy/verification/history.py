from __future__ import annotations

from typing import Any


def update_history(
    history: dict[str, Any], results: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    configs_history = history.setdefault("configs", {})
    for result in results:
        rec = configs_history.setdefault(result["fingerprint"], {"observations": []})
        rec["sources"] = sorted(set(result.get("candidate_sources", [])) - {"previous-output"})
        passed = bool(result["final"]["passed"])
        observation = {
            "timestamp": now,
            "vantage": "ru",
            "passed": passed,
            "reason": result["final"]["reason"],
            "latency": result.get("latency"),
            "r1_kbps": result.get("r1", {}).get("speed_kbps"),
            "r2_kbps": result.get("r2", {}).get("speed_kbps"),
        }
        rec["observations"] = [*rec.get("observations", []), observation][-16:]
        rec["last_seen"] = now
        if passed:
            rec["last_pass"] = now
        observations = rec["observations"]
        recent = observations[-4:]
        rec["availability"] = round(
            sum(item["passed"] for item in observations) / len(observations), 4
        )
        rec["recent_availability"] = round(sum(item["passed"] for item in recent) / len(recent), 4)
        rec["consecutive_pass"] = 0
        rec["consecutive_fail"] = 0
        for item in reversed(observations):
            key = "consecutive_pass" if item["passed"] else "consecutive_fail"
            opposite = "consecutive_fail" if item["passed"] else "consecutive_pass"
            if rec[opposite]:
                break
            rec[key] += 1
        rec["confidence"] = round(min(1.0, len(observations) / 8), 4)

    return configs_history
