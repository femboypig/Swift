from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from swiftproxy.collection.parsing import deduplicate, extract_uris, parse_sources
from swiftproxy.models import ProxyConfig, RankedConfig, SourceResult, SourceSpec, TestResult
from swiftproxy.output import (
    check_outputs,
    country_ordered,
    display_name,
    happ_subscription,
    plain_subscription,
)
from swiftproxy.protocols.parser import parse_uri
from swiftproxy.protocols.serialization import serialize_uri
from swiftproxy.protocols.singbox import sing_box_config, sing_box_outbound
from swiftproxy.verification.resolution import resolve_public_host
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

    def test_query_values_are_decoded_once_and_round_trip(self) -> None:
        uri = (
            f"vless://{UUID_A}@{PUBLIC_V4}:443?encryption=none&type=ws&security=tls"
            "&sni=example.com&host=example.com&path=%2Ftoken%25253D"
        )
        config = parse_uri(uri)
        self.assertEqual(config.options["path"], "/token%253D")
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
            vless_uri().replace("type=tcp", "type=websocket").replace("&sni=", "&path=%2Fws&sni=")
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
            f"hysteria://{PUBLIC_V4}:443?auth=test-password&sni=example.com&insecure=1&upmbps=100&downmbps=100#h1",
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

    def test_http_subscription_urls_are_not_proxy_candidates(self) -> None:
        nested = """
            # mirror: https://example.com/commented-sub.txt
            https://example.com/subscription.txt
              http://example.com/legacy-sub
        """
        self.assertEqual(extract_uris(nested), [])
        for value in (
            "https://example.com/subscription.txt",
            "http://example.com/subscription.txt",
            "  https://example.com/subscription.txt  ",
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "unsupported protocol"),
            ):
                parse_uri(value)

    def test_base64_subscription_still_extracts_supported_proxy_uri(self) -> None:
        payload = base64.b64encode(
            f"https://example.com/nested.txt\n{vless_uri()}\n".encode()
        ).decode()
        self.assertEqual(extract_uris(payload), [vless_uri()])

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
    @patch.dict(
        "os.environ",
        {"SWIFT_BIND_INTERFACE": "wlan0", "SWIFT_DIRECT_SOCKS": "127.0.0.1:3065"},
    )
    def test_interface_binding_cannot_be_overridden_by_direct_socks(self) -> None:
        config = parse_uri(vless_uri())
        with self.assertRaisesRegex(ValueError, "incompatible"):
            sing_box_config(config, 23001)

    @patch.dict("os.environ", {"SWIFT_DIRECT_SOCKS": "192.168.2.1:1080"})
    def test_direct_socks_must_be_loopback(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            sing_box_config(parse_uri(vless_uri()), 23001)

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
            parse_uri(f"hysteria://{PUBLIC_V4}:443?auth=test-password&sni=example.com"),
            parse_uri(f"hysteria2://test-password@{PUBLIC_V4}:443?sni=example.com"),
            parse_uri(f"tuic://{UUID_A}:test-password@{PUBLIC_V4}:443?sni=example.com"),
        ]
        self.assertEqual(sing_box_outbound(configs[0])["type"], "shadowsocks")
        self.assertTrue(sing_box_outbound(configs[1])["tls"]["enabled"])
        self.assertEqual(sing_box_outbound(configs[1])["type"], "hysteria")
        self.assertTrue(sing_box_outbound(configs[2])["tls"]["enabled"])
        self.assertEqual(sing_box_outbound(configs[3])["uuid"], UUID_A)


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
        config = parse_uri(f"vless://{UUID_A}@8.8.8.8:443?encryption=none&type=ws&host=example.com")
        config.resolved_ip = "8.8.8.8"
        self.assertIsNone(evidence_for(config, evidence))
        self.assertGreater(evidence_priority("cidr+sni"), evidence_priority("sni"))

    def test_invalid_primary_cidr_feed_uses_the_mirror(self) -> None:
        primary = SourceSpec(
            "primary", "primary", "https://example.com/primary", set(), "white-cidr"
        )
        mirror = SourceSpec("mirror", "mirror", "https://example.com/mirror", set(), "white-cidr")
        results = [SourceResult(primary, "not-a-network"), SourceResult(mirror, self.cidr_feed())]
        evidence = build_evidence(results)
        self.assertEqual(evidence.cidr_source, "mirror")
        self.assertEqual(results[0].error, "INVALID_CIDR_FEED")

    def test_valid_evidence_feeds_are_merged(self) -> None:
        first = SourceSpec("first", "first", "https://example.com/first", set(), "white-cidr")
        second = SourceSpec("second", "second", "https://example.com/second", set(), "white-cidr")
        second_feed = "\n".join(f"46.20.{index}.0/24" for index in range(100))
        evidence = build_evidence(
            [SourceResult(first, self.cidr_feed()), SourceResult(second, second_feed)]
        )
        self.assertEqual(evidence.cidr_sources, ("first", "second"))
        self.assertTrue(evidence.contains("93.184.216.1"))
        self.assertTrue(evidence.contains("46.20.50.1"))

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


class OutputTests(unittest.TestCase):
    def test_numbered_country_names(self) -> None:
        config = parse_uri(vless_uri())
        result = successful_result(config)
        self.assertEqual(display_name(result, 1, ""), "🇩🇪 DE · 001")
        self.assertEqual(display_name(result, 7, "W"), "🇩🇪 DE · W007")
        result.country = None
        self.assertEqual(display_name(result, 2, ""), "🏴‍☠️ ?? · 002")

    def test_country_ordering_precedes_sequential_numbering(self) -> None:
        configs = [
            parse_uri(vless_uri(uuid=uuid))
            for uuid in (UUID_A, UUID_B, "33333333-3333-4333-8333-333333333333")
        ]
        countries = ("FI", None, "DE")
        ranked = []
        for config, country in zip(configs, countries, strict=True):
            result = successful_result(config)
            result.country = country
            ranked.append(RankedConfig(config, "main", result, 90, "active", 1.0))

        ordered = country_ordered(ranked)
        self.assertEqual([item.result.country for item in ordered], ["DE", "FI", None])
        names = [
            display_name(item.result, index, "") for index, item in enumerate(ordered, start=1)
        ]
        self.assertEqual(names, ["🇩🇪 DE · 001", "🇫🇮 FI · 002", "🏴‍☠️ ?? · 003"])

    def test_plain_and_happ_subscriptions(self) -> None:
        lines = [vless_uri()]
        self.assertTrue(plain_subscription(lines).startswith("vless://"))
        happ = happ_subscription(lines, "Swift Main", "https://github.com/femboypig/swift")
        self.assertIn("#profile-title: Swift Main", happ)
        self.assertIn("#profile-update-interval: 1", happ)
        self.assertNotIn("#profile-title", plain_subscription(lines))

    def test_nested_subscription_urls_fail_output_validation(self) -> None:
        valid = vless_uri()
        cases = (
            ("sub/main.txt", "https://example.com/nested.txt\n"),
            ("sub/happ/main.txt", "#profile-title: Swift Main\nhttps://example.com/nested.txt\n"),
            ("sub/white.txt", "http://example.com/nested.txt\n"),
            ("sub/all.txt", "https://example.com/nested.txt\n"),
        )
        for relative, bad_content in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "sub/happ").mkdir(parents=True)
                (root / "sub/main.txt").write_text(valid + "\n")
                (root / "sub/white.txt").write_text("")
                (root / "sub/all.txt").write_text(valid + "\n")
                (root / "sub/happ/main.txt").write_text(
                    happ_subscription([valid], "Swift Main", "https://example.com")
                )
                (root / "sub/happ/white.txt").write_text(
                    happ_subscription([], "Swift White", "https://example.com")
                )
                (root / "stats.json").write_text(
                    json.dumps(
                        {
                            "project": "Swift",
                            "tagline": "Filter the garbage. Keep what works.",
                            "production": {"main": 1, "white": 0},
                        }
                    )
                )
                (root / relative).write_text(bad_content)
                with self.assertRaisesRegex(RuntimeError, "non-proxy URL"):
                    check_outputs(root, 80, 200)


if __name__ == "__main__":
    unittest.main()
