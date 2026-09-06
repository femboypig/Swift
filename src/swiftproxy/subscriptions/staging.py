from __future__ import annotations

import statistics
from collections import Counter

from swiftproxy.output import subscription_lines, write_final_subscriptions
from swiftproxy.storage import write_json
from swiftproxy.verification.history import update_history
from swiftproxy.verification.results import _now
from swiftproxy.verification.selection import select_outputs


def stage_output(
    publication,
    manifest,
    candidates,
    results,
    history,
    settings,
    terminal_counts,
    freshness_candidates,
    freshness_passed,
):
    now = _now()
    configs_history = update_history(history, results, now)
    ranked_items, main, white = select_outputs(candidates, results, configs_history, settings, now)
    candidate_map = {item["fingerprint"]: item for item in candidates}
    passed = [result for result in results if result["final"]["passed"]]
    output_root = publication / "output"
    from swiftproxy.output import country_ordered

    main = country_ordered(main)
    white = country_ordered(white)
    write_final_subscriptions(
        output_root,
        subscription_lines(main, ""),
        subscription_lines(white, "W"),
        "https://github.com/femboypig/Swift",
    )
    all_lines = subscription_lines(ranked_items, "A")
    from swiftproxy.output import plain_subscription
    from swiftproxy.storage import atomic_write

    atomic_write(output_root / "sub/all.txt", plain_subscription(all_lines))
    latencies = sorted(
        item.result.median_latency_ms
        for item in ranked_items
        if item.result.median_latency_ms is not None
    )
    stats = {
        "project": "Swift",
        "tagline": "Filter the garbage. Keep what works.",
        "updated_at": now,
        "collection_updated_at": manifest["collection_updated_at"],
        "publication_updated_at": now,
        "generation_id": manifest["generation_id"],
        "collected": manifest.get("collected", 0),
        "parsed": manifest.get("parsed", 0),
        "unique": len(candidates),
        "tested": len(results),
        "alive": len(ranked_items),
        "main": len(main),
        "white": len(white),
        "production": {"main": len(main), "white": len(white), "all": len(ranked_items)},
        "protocols": dict(sorted(Counter(item.config.protocol for item in ranked_items).items())),
        "sources": dict(
            sorted(
                Counter(
                    source for result in passed for source in result.get("candidate_sources", [])
                ).items()
            )
        ),
        "countries": dict(
            sorted(
                Counter(item.result.country for item in ranked_items if item.result.country).items()
            )
        ),
        "median_latency_ms": (round(statistics.median(latencies), 2) if latencies else None),
        "failure_reasons": dict(sorted(terminal_counts.items())),
        "freshness": {
            "expected": len(freshness_candidates),
            "passed": freshness_passed,
            "failed": len(freshness_candidates) - freshness_passed,
        },
        "white_evidence": dict(
            sorted(
                Counter(
                    result.get("white", {}).get("evidence") or "upstream-only"
                    for result in passed
                    if "white" in candidate_map[result["fingerprint"]]["lanes"]
                ).items()
            )
        ),
        "funnel": {
            "ru_expected": len(candidates),
            "ru_accounted": len(results),
            "ru_pass": len(ranked_items),
            "main_published": len(main),
            "white_published": len(white),
        },
        "published": False,
        "stage": "ru_complete",
    }
    write_json(output_root / "stats.json", stats)
    write_json(output_root / "data/ru-history.json", history, compact=True)
    return stats
