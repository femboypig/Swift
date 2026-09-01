from __future__ import annotations

import asyncio
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swiftproxy.generation import SCHEMA_VERSION, history_tier
from swiftproxy.models import ProxyConfig
from swiftproxy.output import happ_subscription, plain_subscription
from swiftproxy.parsing import parse_uri, serialize_uri
from swiftproxy.publication import PublicationError, validate_publication
from swiftproxy.ru_golden import _http_probe, _https_session, endpoint_sanity, resolve_ru
from swiftproxy.ru_golden import DownloadGovernor, _white_signal, download_failure_reason


UUID_A = "11111111-1111-4111-8111-111111111111"


def uri(host: str = "93.184.216.34") -> str:
    return f"vless://{UUID_A}@{host}:443?encryption=none&security=none"


class ResolutionTests(unittest.TestCase):
    def test_private_literal_is_accounted_as_unsafe(self) -> None:
        config = ProxyConfig("vless", "127.0.0.1", 443, {"uuid": UUID_A})
        result = asyncio.run(resolve_ru(config, 1))
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "NO_SAFE_ADDRESS")

    @patch("asyncio.BaseEventLoop.getaddrinfo", new_callable=AsyncMock)
    def test_mixed_dns_selects_safe_answer_without_changing_identity(self, lookup) -> None:
        lookup.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ]
        config = parse_uri(uri("proxy.example"))
        fingerprint = config.fingerprint
        result = asyncio.run(resolve_ru(config, 1))
        config.resolved_ip = result["selected_ip"]
        self.assertTrue(result["success"])
        self.assertEqual(result["selected_ip"], "93.184.216.34")
        self.assertEqual(config.fingerprint, fingerprint)
        self.assertEqual(len(result["rejected_answers"]), 1)

    def test_udp_protocols_do_not_receive_tcp_gate(self) -> None:
        values = (
            "hysteria2://password@93.184.216.34:443?sni=example.com",
            f"tuic://{UUID_A}:password@93.184.216.34:443?sni=example.com",
        )
        for value in values:
            with self.subTest(value=value):
                result = asyncio.run(endpoint_sanity(parse_uri(value), 0.01))
                self.assertFalse(result["applicable"])
                self.assertFalse(result["attempted"])


class GoldenHttpsTests(unittest.TestCase):
    @patch("asyncio.create_subprocess_exec")
    def test_http_error_is_not_proxy_success(self, spawn) -> None:
        process = AsyncMock()
        process.returncode = 0
        process.communicate.return_value = (
            json.dumps(
                {
                    "response_code": 503,
                    "time_total": 0.1,
                    "time_connect": 0.01,
                    "time_starttransfer": 0.08,
                }
            ).encode(),
            b"",
        )
        spawn.return_value = process
        result = asyncio.run(_http_probe(1080, "https://example.com", 1))
        self.assertFalse(result["success"])
        self.assertEqual(result["failure"], "HTTP_503")

    @patch("swiftproxy.ru_golden._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_golden._http_probe", new_callable=AsyncMock)
    @patch("swiftproxy.ru_golden._start_core", new_callable=AsyncMock)
    def test_distinct_target_success_and_early_stop(self, start, probe, _stop) -> None:
        start.return_value = (AsyncMock(), 1080, {"success": True})
        probe.side_effect = [
            {"target": "one", "success": True},
            {"target": "two", "success": True},
        ]
        records, _ = asyncio.run(_https_session(parse_uri(uri()), "core", 3, 2))
        self.assertEqual(len(records), 2)
        self.assertEqual(probe.await_count, 2)

    def test_download_requirements_and_stall_taxonomy_are_unchanged(self) -> None:
        self.assertEqual(
            download_failure_reason(
                {"success": False, "category": "STALLED", "speed_kbps": 0}, "R1"
            ),
            "STALLED",
        )
        self.assertEqual(
            download_failure_reason({"success": True, "category": None, "speed_kbps": 63.99}, "R2"),
            "TOO_SLOW",
        )
        self.assertIsNone(
            download_failure_reason({"success": True, "category": None, "speed_kbps": 64.0}, "R2")
        )

    @patch("swiftproxy.ru_golden._direct_control", new_callable=AsyncMock)
    def test_local_congestion_is_an_infrastructure_signal(self, control) -> None:
        control.return_value = {"success": True, "latency_ms": 3000, "path_mode": "test"}
        governor = DownloadGovernor(1, 131072, "wlan0", 100)
        result = asyncio.run(governor.control(4.0, 2000))
        self.assertTrue(result["congested"])

    @patch("swiftproxy.ru_golden._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_golden._http_probe", new_callable=AsyncMock)
    @patch("swiftproxy.ru_golden._start_core", new_callable=AsyncMock)
    def test_two_failures_end_initial_stage(self, start, probe, _stop) -> None:
        start.return_value = (AsyncMock(), 1080, {"success": True})
        probe.side_effect = [
            {"target": "one", "success": False},
            {"target": "two", "success": False},
        ]
        records, _ = asyncio.run(_https_session(parse_uri(uri()), "core", 3, 2))
        self.assertEqual(len(records), 2)


class PublicationContractTests(unittest.TestCase):
    def _tree(self, root: Path, count: int = 2) -> tuple[list[dict], list[dict]]:
        (root / "config.toml").write_text("[limits]\nmain = 80\nwhite = 200\n")
        generation = root / "data/ru-generation"
        output = root / "data/ru-publication/output"
        (output / "sub/happ").mkdir(parents=True)
        generation.mkdir(parents=True)
        configs = [
            parse_uri(
                f"vless://{index:08d}-1111-4111-8111-111111111111@93.184.216.{index + 1}:443?encryption=none"
            )
            for index in range(1, count + 1)
        ]
        candidates = [
            {
                "schema_version": SCHEMA_VERSION,
                "fingerprint": config.fingerprint,
                "protocol": config.protocol,
                "uri": serialize_uri(config),
                "sources": ["synthetic"],
                "candidate_sources": ["synthetic"],
                "lanes": ["main", "white"] if index == 0 else ["main"],
            }
            for index, config in enumerate(configs)
        ]
        results = [
            {
                "generation_id": "generation",
                "fingerprint": item["fingerprint"],
                "white": {"evidence": "cidr"} if index == 0 else {},
                "final": {
                    "terminal_state": "PASS",
                    "reason": "PASS",
                    "passed": True,
                    "accounted_for": True,
                },
            }
            for index, item in enumerate(candidates)
        ]
        manifest = {
            "schema_version": 1,
            "generation_id": "generation",
            "head_sha": "head",
            "ru_expected": count,
        }
        (generation / "manifest.json").write_text(json.dumps(manifest))
        (generation / "candidates.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in candidates)
        )
        publication = root / "data/ru-publication"
        (publication / "ru-results.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in results)
        )
        (publication / "result-manifest.json").write_text(
            json.dumps(
                {
                    **manifest,
                    "complete": True,
                    "state": "RU_COMPLETE",
                    "preflight_ok": True,
                    "postflight_ok": True,
                    "accounted_terminal": count,
                }
            )
        )
        lines = [serialize_uri(config) for config in configs]
        (output / "sub/main.txt").write_text(plain_subscription(lines))
        (output / "sub/white.txt").write_text(plain_subscription(lines[:1]))
        (output / "sub/all.txt").write_text(plain_subscription(lines))
        (output / "sub/happ/main.txt").write_text(happ_subscription(lines, "Swift Main", "repo"))
        (output / "sub/happ/white.txt").write_text(
            happ_subscription(lines[:1], "Swift White", "repo")
        )
        return candidates, results

    def test_complete_exact_generation_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self._tree(root)
            validate_publication(root, "head")

    def test_missing_duplicate_unknown_and_incomplete_are_rejected(self) -> None:
        mutations = ("missing", "duplicate", "unknown", "generation", "incomplete")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                _, results = self._tree(root)
                result_path = root / "data/ru-publication/ru-results.jsonl"
                if mutation == "missing":
                    results.pop()
                elif mutation == "duplicate":
                    results.append(results[0])
                elif mutation == "unknown":
                    results[-1]["fingerprint"] = "f" * 64
                elif mutation == "generation":
                    results[-1]["generation_id"] = "stale-generation"
                else:
                    manifest_path = root / "data/ru-publication/result-manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["complete"] = False
                    manifest["state"] = "RU_INCOMPLETE"
                    manifest_path.write_text(json.dumps(manifest))
                result_path.write_text("".join(json.dumps(item) + "\n" for item in results))
                with self.assertRaises(PublicationError):
                    validate_publication(root, "head")

    def test_large_population_has_no_hidden_cap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidates, results = self._tree(root, 1001)
            for result in results[2:]:
                result["final"] = {
                    "terminal_state": "FAIL",
                    "reason": "HTTPS_FAILED",
                    "passed": False,
                    "accounted_for": True,
                }
            publication = root / "data/ru-publication"
            (publication / "ru-results.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in results)
            )
            output = publication / "output/sub"
            lines = [candidates[index]["uri"] for index in range(2)]
            (output / "main.txt").write_text(plain_subscription(lines))
            (output / "all.txt").write_text(plain_subscription(lines))
            (output / "happ/main.txt").write_text(happ_subscription(lines, "Swift Main", "repo"))
            manifest = validate_publication(root, "head")
            self.assertEqual(manifest["ru_expected"], 1001)


class WorkflowTests(unittest.TestCase):
    def test_production_has_no_github_proxy_traffic_stage(self) -> None:
        workflow = (Path(__file__).parents[1] / ".github/workflows/update.yml").read_text()
        self.assertNotIn("swiftproxy.main\n", workflow)
        self.assertNotIn("cloud-collect", workflow)
        self.assertIn("python -m swiftproxy.generation", workflow)
        self.assertIn("python3 -m swiftproxy.ru_golden", workflow)
        self.assertIn("runs-on: [self-hosted, Linux]", workflow)

    def test_legacy_cloud_history_cannot_gate_or_prioritize_ru(self) -> None:
        cloud = {
            "schema_version": 3,
            "configs": {"fingerprint": {"observations": [{"passed": True}]}},
        }
        self.assertEqual(history_tier(cloud, "fingerprint"), 1)
        self.assertEqual(history_tier({"vantage": "ru", "configs": {}}, "new"), 1)

    def test_white_cidr_uses_the_selected_ru_address(self) -> None:
        config = parse_uri(uri("proxy.example"))
        evidence = {"networks": ["93.184.216.0/24"], "domains": []}
        self.assertEqual(_white_signal(config, "93.184.216.34", evidence), "cidr")
        self.assertIsNone(_white_signal(config, "1.1.1.1", evidence))


if __name__ == "__main__":
    unittest.main()
