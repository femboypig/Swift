from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .main import load_json, load_settings, previous_subscription_configs
from .output import atomic_write, write_json
from .parsing import deduplicate, parse_sources, parse_uri, serialize_uri
from .sources import fetch_sources, source_specs
from .scoring import empty_history
from .testing import sing_box_config
from .whitelist import build_evidence, evidence_specs


SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _head(root: Path) -> str:
    value = os.environ.get("GITHUB_SHA", "").strip()
    if value:
        return value
    process = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return process.stdout.strip()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def history_tier(history: dict[str, Any], fingerprint: str) -> int:
    if history.get("vantage") != "ru":
        return 1
    record = history.get("configs", {}).get(fingerprint)
    if not record:
        return 1
    observations = record.get("observations", [])
    if observations and observations[-1].get("passed"):
        return 0
    return 2 if any(item.get("passed") for item in observations[-3:]) else 3


async def collect_generation(root: Path, config_path: Path) -> dict[str, Any]:
    settings = load_settings(config_path)
    specs = source_specs(settings)
    source_results, evidence_results = await asyncio.gather(
        fetch_sources(specs, float(settings["collection"]["fetch_timeout"])),
        fetch_sources(
            evidence_specs(settings),
            float(settings["white_evidence"]["fetch_timeout"]),
        ),
    )
    if not any(not result.error for result in source_results):
        raise RuntimeError("all proxy sources failed")
    evidence = build_evidence(evidence_results)
    parsed, failures, collected = parse_sources(source_results)
    parsed_count = len(parsed)
    current_sources: dict[str, set[str]] = {}
    current_lanes: dict[str, set[str]] = {}
    for config in parsed:
        current_sources.setdefault(config.fingerprint, set()).update(config.sources)
        current_lanes.setdefault(config.fingerprint, set()).update(config.lanes)

    history = load_json(root / settings["paths"]["history"], empty_history())
    allowed_sources = {
        lane: {spec.name for spec in specs if lane in spec.lanes} for lane in ("main", "white")
    }
    retained = previous_subscription_configs(root, history, allowed_sources)
    parsed.extend(retained)
    unique, duplicates = deduplicate(parsed)
    ru_history_path = root / "data/ru-history.json"
    ru_history = (
        json.loads(ru_history_path.read_text())
        if ru_history_path.exists()
        else {"schema_version": 1, "vantage": "ru", "configs": {}}
    )
    if ru_history.get("vantage") != "ru":
        ru_history = {"schema_version": 1, "vantage": "ru", "configs": {}}

    records: list[dict[str, Any]] = []
    static_rejected = 0
    for config in sorted(unique, key=lambda item: item.fingerprint):
        try:
            sing_box_config(config, 20000)
            uri = serialize_uri(config)
            if parse_uri(uri).fingerprint != config.fingerprint:
                failures["SERIALIZATION_UNSTABLE"] += 1
                static_rejected += 1
                continue
        except (KeyError, TypeError, ValueError):
            static_rejected += 1
            continue
        records.append(
            {
                "schema_version": SCHEMA_VERSION,
                "fingerprint": config.fingerprint,
                "protocol": config.protocol,
                "uri": uri,
                "sources": sorted(current_sources.get(config.fingerprint, set())),
                "candidate_sources": sorted(config.sources),
                "lanes": sorted(config.lanes),
                "current_lanes": sorted(current_lanes.get(config.fingerprint, set())),
                "present_in_current_sources": config.fingerprint in current_sources,
                "retained": config.fingerprint not in current_sources,
                "upstream_white_label": "white" in current_lanes.get(config.fingerprint, set()),
                "scheduling_tier": history_tier(ru_history, config.fingerprint),
            }
        )

    records.sort(key=lambda record: (record["scheduling_tier"], record["fingerprint"]))

    timestamp = _now()
    head = _head(root)
    identity = {
        "head_sha": head,
        "collection_updated_at": timestamp,
        "fingerprints": [record["fingerprint"] for record in records],
        "lanes": [record["lanes"] for record in records],
    }
    generation_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generation_id": generation_id,
        "head_sha": head,
        "collection_updated_at": timestamp,
        "canonical_population": len(records),
        "ru_expected": len(records),
        "main_membership": sum("main" in record["lanes"] for record in records),
        "white_membership": sum("white" in record["lanes"] for record in records),
        "shared_membership": sum({"main", "white"}.issubset(record["lanes"]) for record in records),
        "collected": collected,
        "parsed": parsed_count,
        "parse_failures": dict(sorted(failures.items())),
        "duplicates": duplicates,
        "static_rejected": static_rejected,
    }
    directory = root / "data/ru-generation"
    atomic_write(
        directory / "candidates.jsonl",
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records
        ),
    )
    write_json(directory / "manifest.json", manifest)
    write_json(
        directory / "white-evidence.json",
        {
            "networks": [str(network) for network in evidence.networks],
            "domains": sorted(evidence.domains),
            "cidr_source": evidence.cidr_source,
            "domain_source": evidence.domain_source,
            "cidr_sources": list(evidence.cidr_sources),
            "domain_sources": list(evidence.domain_sources),
        },
        compact=True,
    )
    return manifest


def cli() -> int:
    root = Path.cwd()
    manifest = asyncio.run(collect_generation(root, root / "config.toml"))
    print(f"prepared_ru_generation={manifest['generation_id']} expected={manifest['ru_expected']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
