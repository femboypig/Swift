from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swiftproxy.models import SourceResult, SourceSpec
from swiftproxy.generation import collect_generation
from swiftproxy.protocols.parser import parse_uri
from swiftproxy.publication import validate_publication
from swiftproxy.storage import load_settings, read_jsonl, write_json, write_jsonl
from swiftproxy.verification.candidate import CandidateVerifier
from swiftproxy.verification.health import PathHealth
from swiftproxy.verification.pipeline import run_generation
from swiftproxy.verification.preflight import PathPreflightResult


ROOT = Path(__file__).parents[1]


def candidate(index: int = 1) -> dict:
    uri = f"vless://{index:08d}-1111-4111-8111-111111111111@8.8.8.8:443?security=tls"
    config = parse_uri(uri)
    return {
        "fingerprint": config.fingerprint,
        "uri": uri,
        "protocol": "vless",
        "sources": ["synthetic"],
        "candidate_sources": ["synthetic"],
        "lanes": ["main", "white"],
        "upstream_white_label": True,
    }


def healthy() -> tuple[PathHealth, list[dict]]:
    return PathHealth(
        PathPreflightResult(True, "wlan0", True, 3, 3, True),
        {"success": True, "latency_ms": 100, "path_mode": "bound-interface"},
        {"success": True},
    ), [{"healthy": True}]


def https_success() -> list[dict]:
    return [
        {"target": target, "success": True, "status": 204, "total_ms": 100}
        for target in ("gstatic", "cloudflare")
    ]


class VerificationPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def execute(
        self,
        count: int,
        *,
        fail_index: int | None = None,
        freshness_ok: bool = True,
        congested: bool = False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.toml").write_text((ROOT / "config.toml").read_text())
            items = [candidate(index + 1) for index in range(count)]
            write_json(
                root / "data/ru-generation/manifest.json",
                {
                    "generation_id": "synthetic",
                    "head_sha": "head",
                    "ru_expected": count,
                    "collection_updated_at": "2026-09-06T00:00:00Z",
                },
            )
            write_jsonl(root / "data/ru-generation/candidates.jsonl", items)
            write_json(
                root / "data/ru-generation/white-evidence.json",
                {
                    "networks": ["8.8.8.0/24"],
                    "domains": [],
                },
            )

            async def session(config, *_):
                if (
                    fail_index is not None
                    and config.fingerprint == items[fail_index]["fingerprint"]
                ):
                    return [], {"success": True}
                return https_success(), {"success": True}

            download = {"success": True, "status": 200, "bytes": 262144, "speed_kbps": 128}
            with (
                patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"}),
                patch(
                    "swiftproxy.verification.pipeline._wait_for_healthy_path",
                    AsyncMock(return_value=healthy()),
                ),
                patch(
                    "swiftproxy.verification.scheduler._wait_for_healthy_path",
                    AsyncMock(return_value=healthy()),
                ),
                patch(
                    "swiftproxy.verification.candidate.resolve_ru",
                    AsyncMock(return_value={"success": True, "selected_ip": "8.8.8.8"}),
                ),
                patch(
                    "swiftproxy.verification.candidate.endpoint_sanity",
                    AsyncMock(return_value={"success": False}),
                ),
                patch(
                    "swiftproxy.verification.candidate._https_session", side_effect=session
                ) as sessions,
                patch(
                    "swiftproxy.verification.candidate._start_core",
                    AsyncMock(return_value=(object(), 12345, {"success": True})),
                ),
                patch("swiftproxy.verification.candidate._stop_process", AsyncMock()),
                patch(
                    "swiftproxy.verification.candidate._download", AsyncMock(return_value=download)
                ),
                patch(
                    "swiftproxy.verification.candidate._service_session",
                    AsyncMock(return_value={"geo": {"country": "FI"}}),
                ),
                patch(
                    "swiftproxy.verification.limits.DownloadGovernor.control",
                    AsyncMock(return_value={"congested": congested}),
                ),
                patch(
                    "swiftproxy.verification.scheduler._freshness_check",
                    AsyncMock(
                        return_value={
                            "passed": freshness_ok,
                            "core": {"success": True},
                            "attempts": https_success(),
                        }
                    ),
                ),
            ):
                code = await run_generation(root, "synthetic-core")
                self.assertEqual(code, 0)
                validate_publication(root, "head")
            output = root / "data/ru-publication"
            return (
                json.loads((output / "output/stats.json").read_text()),
                read_jsonl(output / "ru-results.jsonl"),
                sessions.call_count,
            )

    async def test_shared_lanes_are_verified_once_and_failed_tcp_is_only_telemetry(self):
        stats, results, calls = await self.execute(1)
        self.assertEqual((stats["main"], stats["white"], stats["alive"]), (1, 1, 1))
        self.assertEqual(len(results), 1)
        self.assertEqual(calls, 2)

    async def test_all_candidates_are_accounted_before_output_caps(self):
        stats, results, _ = await self.execute(85, fail_index=84)
        self.assertEqual(len(results), 85)
        self.assertEqual((stats["main"], stats["white"], stats["alive"]), (80, 84, 84))
        failed = next(r for r in results if r["fingerprint"] == candidate(85)["fingerprint"])
        self.assertFalse(failed["final"]["passed"])

    async def test_freshness_failure_revokes_pass_before_publication(self):
        stats, results, _ = await self.execute(1, freshness_ok=False)
        self.assertEqual(stats["alive"], 0)
        self.assertEqual(results[0]["final"]["reason"], "FRESHNESS_FAILED")

    async def test_one_local_congestion_deferral_does_not_hold_otherwise_complete_run(self):
        stats, results, _ = await self.execute(1, congested=True)
        self.assertEqual(stats["alive"], 0)
        self.assertEqual(results[0]["final"]["reason"], "DEFER_LOCAL_CONGESTION")

    async def test_unsafe_candidate_never_reaches_network(self):
        item = candidate()
        item["uri"] += "&insecure=1"
        item["fingerprint"] = parse_uri(item["uri"]).fingerprint
        settings = load_settings(ROOT / "config.toml")
        verifier = CandidateVerifier(
            "core", {"generation_id": "test"}, settings, {}, {}, healthy()[0].control, "wlan0"
        )
        with patch("swiftproxy.verification.candidate.resolve_ru", AsyncMock()) as resolve:
            result = await verifier.bounded(item)
        self.assertEqual(result["final"]["reason"], "CONFIG_REJECTED")
        resolve.assert_not_called()

    async def test_collection_filters_insecure_configs_without_changing_credentials(self):
        good = candidate()["uri"]
        source = SourceSpec("test", "test", "https://example.com", {"main"})
        feed = SourceResult(source, content=good + "\n" + good + "&insecure=1")
        evidence = SourceResult(
            SourceSpec("white-cidr-test", "test", "https://example.com", set(), "white-cidr"),
            content="\n".join(f"8.8.{index}.0/24" for index in range(100)),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch(
                    "swiftproxy.generation.fetch_sources",
                    AsyncMock(side_effect=[[feed], [evidence]]),
                ),
                patch("swiftproxy.generation._head", return_value="head"),
            ):
                manifest = await collect_generation(root, ROOT / "config.toml")
            records = read_jsonl(root / "data/ru-generation/candidates.jsonl")
        self.assertEqual(manifest["parse_failures"]["UNSAFE_CONFIG"], 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["fingerprint"], parse_uri(good).fingerprint)
