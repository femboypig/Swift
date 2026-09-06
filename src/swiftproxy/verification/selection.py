from __future__ import annotations

import math
from typing import Any
from urllib.parse import unquote

from swiftproxy.models import RankedConfig, TestResult
from swiftproxy.protocols.parser import parse_uri
from swiftproxy.scoring import diverse_selection, ru_quality_score
from swiftproxy.whitelist import _white_publishable


def select_outputs(candidates, results, configs_history, settings, now):
    candidate_map = {item["fingerprint"]: item for item in candidates}
    passed = [result for result in results if result["final"]["passed"]]

    def score(result: dict[str, Any]) -> float:
        return ru_quality_score(result, configs_history[result["fingerprint"]]["observations"])

    ranked = sorted(passed, key=lambda result: (-math.floor(score(result)), result["fingerprint"]))
    from swiftproxy.output import extract_country_from_remark

    ranked_items: list[RankedConfig] = []
    for result in ranked:
        raw_uri = candidate_map[result["fingerprint"]]["uri"]
        config = parse_uri(raw_uri)
        config.resolved_ip = result["resolution"]["selected_ip"]
        fragment = unquote(raw_uri.split("#")[-1]) if "#" in raw_uri else ""
        geo_country = result.get("services", {}).get("geo", {}).get("country")
        country = (
            geo_country
            if (geo_country and len(geo_country) == 2 and geo_country.isalpha())
            else extract_country_from_remark(fragment)
        )
        test_result = TestResult(
            config.fingerprint,
            "main",
            now,
            success_count=1,
            rounds_attempted=1,
            rounds_succeeded=1,
            median_latency_ms=result["latency"]["median_ms"],
            p95_latency_ms=result["latency"]["p95_ms"],
            jitter_ms=result["latency"]["jitter_ms"],
            throughput_bps=min(result["r1"]["speed_kbps"], result["r2"]["speed_kbps"]) * 1024,
            country=country,
            asn=result.get("services", {}).get("geo", {}).get("asn"),
            provider=result.get("services", {}).get("geo", {}).get("provider"),
        )
        ranked_items.append(RankedConfig(config, "main", test_result, score(result), "active", 1.0))
    limits = settings["limits"]
    diversity = settings["diversity"]
    main_pool = [
        item for item in ranked_items if "main" in candidate_map[item.config.fingerprint]["lanes"]
    ]
    white_pool = [
        item
        for item in ranked_items
        if "white" in candidate_map[item.config.fingerprint]["lanes"]
        and (
            white := next(
                result for result in results if result["fingerprint"] == item.config.fingerprint
            ).get("white", {})
        )
        and _white_publishable(white)
    ]
    main = diverse_selection(
        main_pool,
        int(limits["main"]),
        int(diversity["endpoint"]),
        int(diversity["subnet"]),
        int(diversity["asn"]),
    )
    white = diverse_selection(
        white_pool,
        int(limits["white"]),
        int(diversity["endpoint"]),
        int(diversity["subnet"]),
        int(diversity["asn"]),
    )
    return ranked_items, main, white
