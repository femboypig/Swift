from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from swiftproxy.models import ProxyConfig, TestResult
from swiftproxy.scoring import add_observation, empty_history, rank_configs
from swiftproxy.telemetry import cloud_result_record, population_record, write_jsonl


class TelemetryTests(unittest.TestCase):
    def config(self) -> ProxyConfig:
        return ProxyConfig(
            protocol="vless",
            host="edge.example.com",
            port=443,
            auth={"uuid": "11111111-1111-4111-8111-111111111111"},
            options={
                "security": "reality",
                "public_key": "synthetic-private-looking-value",
                "short_id": "a1b2c3d4",
            },
            sources={"source-a", "source-b"},
            lanes={"main", "white"},
        )

    def result(self, config: ProxyConfig) -> TestResult:
        return TestResult(
            fingerprint=config.fingerprint,
            lane="main",
            timestamp="2026-09-01T00:00:00Z",
            rounds_attempted=2,
            rounds_succeeded=2,
            success_count=10,
            median_latency_ms=90,
            p95_latency_ms=110,
            jitter_ms=8,
            throughput_bps=300_000,
            round_diagnostics=[
                {
                    "round": 1,
                    "targets": [
                        {
                            "target": "gstatic",
                            "distinct": True,
                            "success": False,
                            "failure": "CURL_28",
                        }
                    ],
                    "throughput": {"attempted": False, "success": False},
                    "core_start": None,
                }
            ],
        )

    def test_population_distinguishes_resolution_and_white_evidence(self) -> None:
        config = self.config()
        failed = population_record(
            config,
            {"source-a", "source-b"},
            {"main", "white"},
            {"main", "white"},
            "DNS_FAILED",
            "cidr+sni",
        )
        self.assertTrue(failed["parsed_present"])
        self.assertTrue(failed["resolution"]["attempted"])
        self.assertFalse(failed["resolution"]["success"])
        self.assertEqual(failed["resolution"]["reason"], "DNS_FAILED")
        self.assertEqual(failed["white"]["evidence"], "cidr+sni")
        self.assertTrue(failed["white"]["upstream_label"])

        config.resolved_ip = "93.184.216.34"
        resolved = population_record(
            config,
            {"source-a", "source-b"},
            {"main", "white"},
            {"main", "white"},
            "DNS_FAILED",
            "sni",
        )
        self.assertTrue(resolved["resolution"]["success"])
        self.assertIsNone(resolved["resolution"]["reason"])
        self.assertEqual(resolved["resolution"]["resolved_ip"], "93.184.216.34")

        retained = population_record(config, set(), set(), {"main", "white"}, None, None)
        self.assertFalse(retained["parsed_present"])
        self.assertEqual(retained["sources"], [])
        self.assertEqual(retained["candidate_sources"], ["source-a", "source-b"])

    def test_cloud_rounds_are_per_fingerprint_and_do_not_contain_credentials(self) -> None:
        config = self.config()
        result = self.result(config)
        record = cloud_result_record(config, result)
        self.assertEqual(record["fingerprint"], config.fingerprint)
        self.assertEqual(record["rounds"][0]["round"], 1)
        self.assertEqual(record["rounds"][0]["targets"][0]["failure"], "CURL_28")
        serialized = json.dumps(record)
        self.assertNotIn(str(config.auth["uuid"]), serialized)
        self.assertNotIn(str(config.options["public_key"]), serialized)
        self.assertNotIn("vless://", serialized)

    def test_jsonl_is_current_run_only_and_sorted_by_caller(self) -> None:
        config = self.config()
        record = cloud_result_record(config, self.result(config))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".swift-forensics/cloud-results.jsonl"
            write_jsonl(path, [record])
            written = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(written, [record])

    def test_telemetry_fields_do_not_change_ranking(self) -> None:
        config = self.config()
        result = self.result(config)
        history = empty_history()
        add_observation(history, config, result, 16)
        add_observation(history, config, result, 16)
        baseline = rank_configs(
            [config], {(config.fingerprint, "main"): result}, history, "main", [], 0, 0
        )
        result.round_diagnostics.append({"round": 2, "targets": []})
        result.core_start_failures.append({"category": "CORE_EXITED", "exit_code": 1})
        observed = rank_configs(
            [config], {(config.fingerprint, "main"): result}, history, "main", [], 0, 0
        )
        self.assertEqual(
            [item.config.fingerprint for item in baseline],
            [item.config.fingerprint for item in observed],
        )


if __name__ == "__main__":
    unittest.main()
