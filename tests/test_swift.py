from __future__ import annotations

import base64
import json
import tempfile
import unittest
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote
from unittest.mock import AsyncMock, patch

from swiftproxy.models import ProxyConfig, RankedConfig, SourceResult, SourceSpec, TestResult
from swiftproxy.main import previous_subscription_configs
from swiftproxy.output import (
    HAPP_PROTOCOLS,
    PIPELINE_VERSION,
    alive_for_all,
    display_name,
    happ_subscription,
    plain_subscription,
    suspicious_run,
    write_subscriptions,
)
from swiftproxy.parsing import (
    deduplicate,
    extract_uris,
    parse_sources,
    parse_uri,
    serialize_uri,
)
from swiftproxy.scoring import (
    add_observation,
    choose_candidates,
    diverse_selection,
    empty_history,
    rank_configs,
    score_lane,
    state_after,
)
from swiftproxy.testing import resolve_public_host, sing_box_config, sing_box_outbound
from swiftproxy.whitelist import build_evidence, evidence_for, evidence_priority


UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def vless_uri(host: str = PUBLIC_V4, *, uuid: str = UUID_A, remark: str = "upstream") -> str:
    endpoint = f"[{host}]" if ":" in host else host
    return (
        f"vless://{uuid}@{endpoint}:443?encryption=none&security=reality&type=tcp"
        f"&sni=example.com&fp=chrome&pbk=abc_DEF-123&sid=0a1b#{quote(remark)}"
    )


def successful_result(config: ProxyConfig, lane: str = "main", latency: float = 70) -> TestResult:
    return TestResult(
        config.fingerprint,
        lane,
        "2026-08-27T12:00:00Z",
        rounds_attempted=2,
        rounds_succeeded=2,
        success_count=5,
        failure_count=0,
        latencies_ms=[latency - 2, latency, latency + 1, latency + 2, latency + 3],
        median_latency_ms=latency + 1,
        p95_latency_ms=latency + 3,
        min_latency_ms=latency - 2,
        max_latency_ms=latency + 3,
        jitter_ms=2.0,
        throughput_bps=1_500_000,
        country="DE",
        asn=64501,
        provider="Synthetic Network",
    )


class ParsingTests(unittest.TestCase):
    def test_vless_reality_round_trip_and_name_encoding(self) -> None:
        config = parse_uri(vless_uri())
        self.assertEqual(config.protocol, "vless")
        self.assertEqual(config.options["security"], "reality")
        serialized = serialize_uri(config, "DE | Reality | A1B2C3")
        reparsed = parse_uri(serialized)
        self.assertEqual(config.fingerprint, reparsed.fingerprint)
        self.assertIn("#DE%20%7C%20Reality%20%7C%20A1B2C3", serialized)

    def test_vless_packet_encoding_and_spider_x_round_trip(self) -> None:
        uri = vless_uri().replace("#", "&packetEncoding=xudp&spx=%2F#")
        config = parse_uri(uri)
        self.assertEqual(config.options["packet_encoding"], "xudp")
        self.assertEqual(config.options["spider_x"], "/")
        self.assertEqual(config.fingerprint, parse_uri(serialize_uri(config)).fingerprint)

    def test_parameter_order_and_remark_do_not_change_fingerprint(self) -> None:
        first = parse_uri(vless_uri(remark="one"))
        second = parse_uri(
            f"vless://{UUID_A}@{PUBLIC_V4}:443?sid=0a1b&pbk=abc_DEF-123&fp=chrome"
            "&type=tcp&sni=example.com&security=reality&encryption=none#two"
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_xray_transport_names_are_normalized(self) -> None:
        raw = parse_uri(vless_uri().replace("type=tcp", "type=raw"))
        websocket = parse_uri(
            vless_uri()
            .replace("type=tcp", "type=websocket")
            .replace("&sni=", "&path=%2Fws&sni=")
        )
        self.assertEqual(raw.options["transport"], "tcp")
        self.assertEqual(websocket.options["transport"], "ws")
        self.assertEqual(raw.fingerprint, parse_uri(vless_uri()).fingerprint)
        self.assertEqual(raw.fingerprint, parse_uri(serialize_uri(raw)).fingerprint)

    def test_vmess_round_trip(self) -> None:
        payload = {
            "v": "2",
            "ps": "synthetic",
            "add": PUBLIC_V4,
            "port": "443",
            "id": UUID_A,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/proxy",
            "tls": "tls",
            "sni": "cdn.example.com",
            "fp": "chrome",
            "skip-cert-verify": True,
            "packetEncoding": "xudp",
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        config = parse_uri(f"vmess://{encoded}")
        self.assertEqual(config.options["transport"], "ws")
        self.assertTrue(config.options["insecure"])
        self.assertEqual(config.options["packet_encoding"], "xudp")
        self.assertEqual(config.fingerprint, parse_uri(serialize_uri(config)).fingerprint)

    def test_other_protocol_round_trips(self) -> None:
        method = base64.urlsafe_b64encode(b"aes-128-gcm:test-password").decode().rstrip("=")
        uris = [
            f"trojan://test-password@{PUBLIC_V4}:443?security=tls&sni=example.com&type=tcp#t",
            f"ss://{method}@{PUBLIC_V4}:8388#s",
            f"hysteria2://test-password@{PUBLIC_V4}:443?sni=example.com&insecure=1#h",
            f"tuic://{UUID_A}:test-password@{PUBLIC_V4}:443?sni=example.com&congestion_control=bbr#u",
        ]
        for uri in uris:
            with self.subTest(uri=uri.split(":", 1)[0]):
                config = parse_uri(uri)
                self.assertEqual(config.fingerprint, parse_uri(serialize_uri(config)).fingerprint)

    def test_legacy_shadowsocks_payload(self) -> None:
        raw = f"aes-256-gcm:password@{PUBLIC_V4}:8388".encode()
        uri = "ss://" + base64.b64encode(raw).decode()
        config = parse_uri(uri)
        self.assertEqual(config.auth["password"], "password")
        self.assertEqual(config.options["method"], "aes-256-gcm")

    def test_ipv4_ipv6_and_hostname(self) -> None:
        self.assertEqual(parse_uri(vless_uri(PUBLIC_V4)).host, PUBLIC_V4)
        self.assertEqual(parse_uri(vless_uri(PUBLIC_V6)).host, PUBLIC_V6)
        self.assertEqual(parse_uri(vless_uri("edge.example.com")).host, "edge.example.com")

    def test_private_and_local_endpoints_are_rejected(self) -> None:
        rejected = ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::1", "localhost"]
        for host in rejected:
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "private endpoint"):
                parse_uri(vless_uri(host))

    def test_malformed_and_unsupported_input(self) -> None:
        bad = [
            "not-a-uri",
            f"vless://{UUID_A}@{PUBLIC_V4}:0?encryption=none",
            f"vless://bad-uuid@{PUBLIC_V4}:443?encryption=none",
            f"vless://{UUID_A}@{PUBLIC_V4}:443?type=xhttp&encryption=none",
            f"vless://{UUID_A}@{PUBLIC_V4}:443?type=tcp&headerType=http&encryption=none",
            f"trojan://password@{PUBLIC_V4}:443?security=tls#bad\x00name",
            f"ss://YWVzLTEyOC1nY206cGFzcw@{PUBLIC_V4}:8388?plugin=/tmp/evil",
        ]
        for uri in bad:
            with self.subTest(uri=uri[:30]), self.assertRaises(ValueError):
                parse_uri(uri)

    def test_extracts_plain_base64_and_metadata_prefixed_lists(self) -> None:
        content = f"#profile-title: Test\n{vless_uri()}\n"
        self.assertEqual(len(extract_uris(content)), 1)
        encoded = base64.b64encode(content.encode()).decode()
        self.assertEqual(len(extract_uris(encoded)), 1)
        html = f'<input value="{vless_uri()}">'
        self.assertEqual(len(extract_uris(html, "html")), 1)

    def test_source_parsing_and_deduplication_merge_provenance_and_lanes(self) -> None:
        main = SourceSpec("main", "source-a", "https://example.com/a", {"main"})
        white = SourceSpec("white", "source-b", "https://example.com/b", {"white"})
        configs, reasons, collected = parse_sources(
            [SourceResult(main, vless_uri(remark="a")), SourceResult(white, vless_uri(remark="b"))]
        )
        unique, duplicates = deduplicate(configs)
        self.assertEqual((collected, len(configs), len(unique), duplicates), (2, 2, 1, 1))
        self.assertEqual(unique[0].sources, {"source-a", "source-b"})
        self.assertEqual(unique[0].lanes, {"main", "white"})
        self.assertFalse(reasons)


class TestingConfigTests(unittest.TestCase):
    def test_sing_box_reality_config_uses_resolved_ip_and_keeps_sni(self) -> None:
        config = parse_uri(vless_uri("edge.example.com"))
        config.resolved_ip = PUBLIC_V4
        outbound = sing_box_outbound(config)
        self.assertEqual(outbound["server"], PUBLIC_V4)
        self.assertEqual(outbound["tls"]["server_name"], "example.com")
        self.assertEqual(outbound["tls"]["reality"]["public_key"], "abc_DEF-123")
        generated = sing_box_config(config, 23001)
        self.assertEqual(generated["route"]["final"], "proxy")
        self.assertEqual(generated["inbounds"][0]["listen"], "127.0.0.1")

        packet_config = parse_uri(vless_uri().replace("#", "&packetEncoding=xudp#"))
        self.assertEqual(sing_box_outbound(packet_config)["packet_encoding"], "xudp")

    def test_sing_box_protocol_mappings(self) -> None:
        method = base64.urlsafe_b64encode(b"aes-128-gcm:test-password").decode().rstrip("=")
        configs = [
            parse_uri(f"ss://{method}@{PUBLIC_V4}:8388"),
            parse_uri(f"hysteria2://test-password@{PUBLIC_V4}:443?sni=example.com"),
            parse_uri(f"tuic://{UUID_A}:test-password@{PUBLIC_V4}:443?sni=example.com"),
        ]
        self.assertEqual(sing_box_outbound(configs[0])["type"], "shadowsocks")
        self.assertTrue(sing_box_outbound(configs[1])["tls"]["enabled"])
        self.assertEqual(sing_box_outbound(configs[2])["uuid"], UUID_A)


class EndpointResolutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_prefers_an_allowlisted_address_from_all_dns_answers(self) -> None:
        answers = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", (PUBLIC_V4, 443)),
        ]
        with patch("asyncio.BaseEventLoop.getaddrinfo", new=AsyncMock(return_value=answers)):
            resolved = await resolve_public_host(
                "edge.example.com", 443, lambda address: address == PUBLIC_V4
            )
        self.assertEqual(resolved, PUBLIC_V4)


class WhiteEvidenceTests(unittest.TestCase):
    @staticmethod
    def cidr_feed() -> str:
        networks = [f"45.10.{index}.0/24" for index in range(100)]
        networks.append("93.184.216.0/24")
        return "\n".join(networks)

    @staticmethod
    def domain_feed() -> str:
        return "\n".join(["example.com", *(f"service{index}.ru" for index in range(49))])

    def test_cidr_membership_and_sni_are_separate_evidence(self) -> None:
        cidr = SourceSpec("cidr", "cidr", "https://example.com/cidr", set(), "white-cidr")
        domains = SourceSpec(
            "domains", "domains", "https://example.com/domains", set(), "white-domains"
        )
        evidence = build_evidence(
            [
                SourceResult(cidr, self.cidr_feed()),
                SourceResult(domains, self.domain_feed()),
            ]
        )
        config = parse_uri(vless_uri())
        config.resolved_ip = PUBLIC_V4
        self.assertEqual(evidence_for(config, evidence), "cidr+sni")
        config.options["sni"] = "not-example.net"
        self.assertEqual(evidence_for(config, evidence), "cidr")
        config.resolved_ip = "8.8.8.8"
        self.assertIsNone(evidence_for(config, evidence))
        config.options["sni"] = "cdn.example.com"
        self.assertEqual(evidence_for(config, evidence), "sni")
        config.resolved_ip = PUBLIC_V6
        self.assertEqual(evidence_for(config, evidence), "sni")

    def test_sni_evidence_requires_a_tls_transport(self) -> None:
        cidr = SourceSpec("cidr", "cidr", "https://example.com/cidr", set(), "white-cidr")
        domains = SourceSpec(
            "domains", "domains", "https://example.com/domains", set(), "white-domains"
        )
        evidence = build_evidence(
            [SourceResult(cidr, self.cidr_feed()), SourceResult(domains, self.domain_feed())]
        )
        config = parse_uri(
            f"vless://{UUID_A}@8.8.8.8:443?encryption=none&type=ws&host=example.com"
        )
        config.resolved_ip = "8.8.8.8"
        self.assertIsNone(evidence_for(config, evidence))
        self.assertGreater(evidence_priority("cidr+sni"), evidence_priority("sni"))

    def test_invalid_primary_cidr_feed_uses_the_mirror(self) -> None:
        primary = SourceSpec(
            "primary", "primary", "https://example.com/primary", set(), "white-cidr"
        )
        mirror = SourceSpec(
            "mirror", "mirror", "https://example.com/mirror", set(), "white-cidr"
        )
        results = [SourceResult(primary, "not-a-network"), SourceResult(mirror, self.cidr_feed())]
        evidence = build_evidence(results)
        self.assertEqual(evidence.cidr_source, "mirror")
        self.assertEqual(results[0].error, "INVALID_CIDR_FEED")

    def test_domain_match_does_not_accept_lookalike_suffixes(self) -> None:
        cidr = SourceSpec("cidr", "cidr", "https://example.com/cidr", set(), "white-cidr")
        domains = SourceSpec(
            "domains", "domains", "https://example.com/domains", set(), "white-domains"
        )
        evidence = build_evidence(
            [SourceResult(cidr, self.cidr_feed()), SourceResult(domains, self.domain_feed())]
        )
        self.assertTrue(evidence.contains_sni("cdn.example.com"))
        self.assertFalse(evidence.contains_sni("notexample.com"))


class ScoringAndHistoryTests(unittest.TestCase):
    def test_stable_config_beats_spiky_low_minimum(self) -> None:
        stable = {
            "observations": [
                {
                    "timestamp": "2026-08-27T12:00:00Z",
                    "success": True,
                    "success_ratio": 1.0,
                    "median_latency": 63,
                    "p95_latency": 66,
                    "jitter": 2,
                    "throughput": 1_000_000,
                }
                for _ in range(8)
            ]
        }
        unstable = {
            "observations": [
                {
                    "timestamp": "2026-08-27T12:00:00Z",
                    "success": True,
                    "success_ratio": 0.6,
                    "median_latency": 35,
                    "p95_latency": 740,
                    "jitter": 290,
                    "throughput": 1_000_000,
                }
                for _ in range(8)
            ]
        }
        now = datetime(2026, 8, 27, 12, 10, tzinfo=UTC)
        self.assertGreater(score_lane(stable, now)[0], score_lane(unstable, now)[0])

    def test_white_score_does_not_depend_on_actions_latency(self) -> None:
        record = {
            "observations": [
                {
                    "timestamp": "2026-08-27T12:00:00Z",
                    "success": True,
                    "success_ratio": 0.8,
                    "rounds": 2,
                    "confirmed_rounds": 2,
                    "median_latency": 4000,
                    "p95_latency": 9000,
                    "jitter": 2500,
                    "throughput": 65536,
                }
            ]
        }
        now = datetime(2026, 8, 27, 12, 10, tzinfo=UTC)
        self.assertGreater(score_lane(record, now, lane="white")[0], 60)
        self.assertLess(score_lane(record, now, lane="main")[0], 70)

    def test_hysteresis_promotes_strong_new_and_graces_one_failure(self) -> None:
        config = parse_uri(vless_uri())
        history = empty_history()
        first = successful_result(config)
        lane = add_observation(history, config, first, 16)
        self.assertEqual(lane["state"], "active")
        failure = TestResult(config.fingerprint, "main", "2026-08-27T12:30:00Z", failure_count=5)
        lane = add_observation(history, config, failure, 16)
        self.assertEqual(lane["state"], "degraded")
        lane = add_observation(history, config, failure, 16)
        self.assertEqual(lane["state"], "dead")

    def test_grace_run_is_not_removed_by_the_temporary_score_drop(self) -> None:
        config = parse_uri(vless_uri())
        config.lanes.add("main")
        history = empty_history()
        lane = add_observation(history, config, successful_result(config), 16)
        lane["score"] = 72
        failure = TestResult(config.fingerprint, "main", "2026-08-27T12:30:00Z", failure_count=5)
        add_observation(history, config, failure, 16)
        ranked = rank_configs(
            [config],
            {(config.fingerprint, "main"): failure},
            history,
            "main",
            [config.fingerprint],
            70,
            131072,
        )
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0].state, "degraded")

    def test_partial_failure_gets_one_grace_run_but_not_two(self) -> None:
        config = parse_uri(vless_uri())
        config.lanes.add("main")
        history = empty_history()
        lane = add_observation(history, config, successful_result(config), 16)
        lane["score"] = 72
        partial = TestResult(
            config.fingerprint,
            "main",
            "2026-08-27T12:30:00Z",
            rounds_attempted=2,
            rounds_succeeded=1,
            success_count=6,
            failure_count=4,
            median_latency_ms=120,
            p95_latency_ms=400,
            jitter_ms=95,
            throughput_bps=160_000,
            reason="UNSTABLE",
        )
        add_observation(history, config, partial, 16)
        ranked = rank_configs(
            [config],
            {(config.fingerprint, "main"): partial},
            history,
            "main",
            [config.fingerprint],
            70,
            131072,
        )
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0].state, "degraded")

        partial.timestamp = "2026-08-27T13:00:00Z"
        add_observation(history, config, partial, 16)
        ranked = rank_configs(
            [config],
            {(config.fingerprint, "main"): partial},
            history,
            "main",
            [config.fingerprint],
            70,
            131072,
        )
        self.assertEqual(ranked, [])

    def test_one_successful_round_does_not_promote_a_new_config(self) -> None:
        config = parse_uri(vless_uri())
        result = successful_result(config)
        result.rounds_succeeded = 1
        lane = add_observation(empty_history(), config, result, 16)
        self.assertEqual(lane["state"], "new")

    def test_history_window_is_bounded(self) -> None:
        config = parse_uri(vless_uri())
        history = empty_history()
        for index in range(20):
            result = successful_result(config)
            result.timestamp = f"2026-08-27T12:{index:02d}:00Z"
            add_observation(history, config, result, 4)
        observations = history["configs"][config.fingerprint]["lanes"]["main"]["observations"]
        self.assertEqual(len(observations), 4)

    def test_candidate_selection_prioritizes_active_but_explores_deterministically(self) -> None:
        active = parse_uri(vless_uri(uuid=UUID_A))
        active.lanes.add("main")
        new = parse_uri(vless_uri(uuid=UUID_B))
        new.lanes.add("main")
        history = empty_history()
        lane = add_observation(history, active, successful_result(active), 16)
        lane["score"] = 90
        chosen_a = choose_candidates([new, active], history, "main", 2, "seed")
        chosen_b = choose_candidates([active, new], history, "main", 2, "seed")
        self.assertEqual(chosen_a[0].fingerprint, active.fingerprint)
        self.assertEqual([item.fingerprint for item in chosen_a], [item.fingerprint for item in chosen_b])

    def test_ranking_preserves_previous_order_inside_score_bucket(self) -> None:
        first = parse_uri(vless_uri(uuid=UUID_A))
        second = parse_uri(vless_uri(uuid=UUID_B))
        for config in (first, second):
            config.lanes.add("main")
        history = empty_history()
        results = {}
        for config in (first, second):
            result = successful_result(config)
            results[(config.fingerprint, "main")] = result
            add_observation(history, config, result, 16)
        previous = [second.fingerprint, first.fingerprint]
        ranked = rank_configs([first, second], results, history, "main", previous, 50, 65536)
        self.assertEqual([item.config.fingerprint for item in ranked], previous)

    def test_diversity_limits_are_soft(self) -> None:
        ranked = []
        for index in range(5):
            config = parse_uri(vless_uri(uuid=f"00000000-0000-4000-8000-{index:012d}"))
            config.resolved_ip = PUBLIC_V4
            result = successful_result(config)
            ranked.append(RankedConfig(config, "main", result, 90 - index, "active", 1.0))
        selected = diverse_selection(ranked, 4, endpoint_limit=1, subnet_limit=1, asn_limit=1)
        self.assertEqual(len(selected), 4)


class OutputTests(unittest.TestCase):
    def test_previous_subscriptions_are_kept_as_candidates(self) -> None:
        config = parse_uri(vless_uri())
        config.sources.add("source-a")
        history = empty_history()
        add_observation(history, config, successful_result(config), 16)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sub").mkdir()
            (root / "sub/main.txt").write_text(serialize_uri(config) + "\n")
            (root / "sub/white.txt").write_text("")
            retained = previous_subscription_configs(root, history)
            removed_source = previous_subscription_configs(
                root,
                history,
                {"main": {"source-b"}, "white": set()},
            )
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].fingerprint, config.fingerprint)
        self.assertEqual(retained[0].lanes, {"main"})
        self.assertEqual(retained[0].sources, {"source-a"})
        self.assertEqual(removed_source, [])

    def test_numbered_country_names(self) -> None:
        config = parse_uri(vless_uri())
        result = successful_result(config)
        self.assertEqual(display_name(result, 1, ""), "🇩🇪 DE · 001")
        self.assertEqual(display_name(result, 7, "W"), "🇩🇪 DE · W007")
        result.country = None
        self.assertEqual(display_name(result, 2, ""), "🏳️ ?? · 002")

    def test_plain_and_happ_subscriptions(self) -> None:
        lines = [vless_uri()]
        self.assertTrue(plain_subscription(lines).startswith("vless://"))
        happ = happ_subscription(lines, "Swift Main", "https://github.com/femboypig/swift")
        self.assertIn("#profile-title: Swift Main", happ)
        self.assertIn("#profile-update-interval: 1", happ)
        self.assertNotIn("#profile-title", plain_subscription(lines))

    def test_subscription_generation_limits_happ_protocols(self) -> None:
        vless = parse_uri(vless_uri())
        tuic = parse_uri(f"tuic://{UUID_B}:test-password@{PUBLIC_V4}:443?sni=example.com")
        history = empty_history()
        ranked = []
        for config in (vless, tuic):
            result = successful_result(config)
            add_observation(history, config, result, 16)
            ranked.append(RankedConfig(config, "main", result, 90, "active", 1.0))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_subscriptions(
                root,
                ranked,
                [],
                ranked,
                "https://github.com/femboypig/swift",
            )
            universal = (root / "sub/main.txt").read_text()
            happ = (root / "sub/happ/main.txt").read_text()
        self.assertIn("tuic://", universal)
        self.assertNotIn("tuic://", happ)
        self.assertIn("vless://", happ)
        self.assertNotIn("tuic", HAPP_PROTOCOLS)

    def test_all_requires_current_proxy_traffic_and_minimum_throughput(self) -> None:
        config = parse_uri(vless_uri())
        good = successful_result(config)
        history = empty_history()
        add_observation(history, config, good, 16)
        results = {(config.fingerprint, "main"): good}
        self.assertEqual(len(alive_for_all([config], results, history, 16384)), 1)
        good.rounds_succeeded = 1
        self.assertEqual(len(alive_for_all([config], results, history, 16384)), 0)
        good.rounds_succeeded = 2
        good.throughput_bps = 100
        self.assertEqual(len(alive_for_all([config], results, history, 16384)), 0)

    def test_mass_failure_holds_previous_subscriptions(self) -> None:
        previous = {
            "pipeline_version": PIPELINE_VERSION,
            "production": {"main": 164, "white": 121, "all": 300},
        }
        reason = suspicious_run(previous, 7, 100, 500, Counter(), 4)
        self.assertEqual(reason, "MAIN_MASS_FAILURE")
        self.assertEqual(
            suspicious_run(previous, 160, 118, 500, Counter(), 4),
            None,
        )
        self.assertEqual(
            suspicious_run(None, 0, 0, 100, Counter({"CORE_START_FAILED": 80}), 4),
            "CORE_FAILURE_RATE",
        )


if __name__ == "__main__":
    unittest.main()
