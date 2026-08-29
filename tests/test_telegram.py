from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from typing import Self
from unittest.mock import patch

from swiftproxy.models import SourceResult, SourceSpec
from swiftproxy.telegram import (
    RankedTelegram,
    TelegramProxy,
    TelegramResult,
    add_observation,
    assess_run,
    deduplicate,
    empty_history,
    fastest_proxies,
    parse_proxy_url,
    score_proxy,
    select_message_targets,
)
from swiftproxy.telegram_main import run
from swiftproxy.telegram_publish import message_payload, publish_status

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"
RAW_SECRET = "11" * 16
DD_SECRET = "dd" + "22" * 16
EE_SECRET = "ee" + "33" * 16 + b"example.com".hex()


def proxy_url(secret: str = DD_SECRET, host: str = PUBLIC_V4, port: int = 443) -> str:
    return f"https://t.me/proxy?server={host}&port={port}&secret={secret}"


def good_result(proxy: TelegramProxy, rtts: list[float] | None = None) -> TelegramResult:
    return TelegramResult(
        proxy.fingerprint,
        "2026-08-28T12:00:00Z",
        attempts=3,
        successes=3,
        rtts_ms=rtts or [98, 100, 103],
    )


class TelegramParsingTests(unittest.TestCase):
    def test_parses_tme_proxy(self) -> None:
        proxy = parse_proxy_url(proxy_url())
        self.assertEqual(proxy.host, PUBLIC_V4)
        self.assertEqual(proxy.port, 443)
        self.assertEqual(proxy.secret, DD_SECRET)
        self.assertEqual(proxy.secret_kind, "secure")

    def test_parses_tg_proxy_and_normalizes_base64_secret(self) -> None:
        encoded = base64.urlsafe_b64encode(bytes.fromhex(DD_SECRET)).decode().rstrip("=")
        proxy = parse_proxy_url(f"tg://proxy?secret={encoded}&port=8443&server={PUBLIC_V4}")
        self.assertEqual(proxy.secret, DD_SECRET)
        self.assertTrue(proxy.url.startswith("https://t.me/proxy?"))

    def test_rejects_invalid_port_and_malformed_secret(self) -> None:
        with self.assertRaisesRegex(ValueError, "INVALID_PORT"):
            parse_proxy_url(proxy_url(port=70000))
        with self.assertRaisesRegex(ValueError, "MALFORMED_SECRET"):
            parse_proxy_url(proxy_url(secret="not-a-secret"))

    def test_rejects_unsupported_extended_secret_separately(self) -> None:
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_SECRET"):
            parse_proxy_url(proxy_url(secret="44" * 20))

    def test_rejects_private_and_local_destinations(self) -> None:
        for host in ("127.0.0.1", "10.0.0.1", "localhost", "::1", "fe80::1"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "PRIVATE_ENDPOINT"):
                parse_proxy_url(proxy_url(host=host))

    def test_accepts_public_ipv6(self) -> None:
        proxy = parse_proxy_url(proxy_url(host=PUBLIC_V6, secret=EE_SECRET))
        self.assertEqual(proxy.host, PUBLIC_V6)
        self.assertEqual(proxy.secret_kind, "faketls")

    def test_deduplicates_by_normalized_identity_and_merges_sources(self) -> None:
        encoded = base64.urlsafe_b64encode(bytes.fromhex(RAW_SECRET)).decode().rstrip("=")
        first = parse_proxy_url(proxy_url(secret=RAW_SECRET))
        second = parse_proxy_url(f"tg://proxy?port=443&server={PUBLIC_V4}&secret={encoded}")
        first.sources.add("one")
        second.sources.add("two")
        unique, duplicates = deduplicate([first, second])
        self.assertEqual(duplicates, 1)
        self.assertEqual(unique[0].sources, {"one", "two"})


class TelegramScoringTests(unittest.TestCase):
    def test_stability_beats_one_spiky_fast_observation(self) -> None:
        stable = {
            "observations": [
                {
                    "attempts": 3,
                    "successes": 3,
                    "median_rtt": 105,
                    "p95_rtt": 110,
                    "jitter": 4,
                    "fresh_source": True,
                }
                for _ in range(8)
            ]
        }
        unstable = {
            "observations": [
                {
                    "attempts": 3,
                    "successes": 2,
                    "median_rtt": 70,
                    "p95_rtt": 1600,
                    "jitter": 710,
                    "fresh_source": True,
                }
            ]
        }
        self.assertGreater(score_proxy(stable, "secure")[0], score_proxy(unstable, "secure")[0])

    def test_stable_promotion_and_three_failure_hysteresis(self) -> None:
        proxy = parse_proxy_url(proxy_url())
        history = empty_history()
        settings = {"window": 24, "promotion_runs": 3, "remove_failures": 3}
        states = []
        for index in range(3):
            result = good_result(proxy)
            result.timestamp = f"2026-08-28T12:0{index}:00Z"
            states.append(add_observation(history, proxy, result, settings)["state"])
        self.assertEqual(states, ["new", "new", "active"])
        failure = TelegramResult(proxy.fingerprint, "2026-08-28T13:00:00Z", attempts=3)
        states = [add_observation(history, proxy, failure, settings)["state"] for _ in range(3)]
        self.assertEqual(states, ["degraded", "degraded", "dead"])

    def test_fastest_penalizes_bad_tail_and_jitter(self) -> None:
        spiky_proxy = parse_proxy_url(proxy_url(secret=RAW_SECRET))
        steady_proxy = parse_proxy_url(proxy_url(secret=DD_SECRET))
        spiky = RankedTelegram(
            spiky_proxy, good_result(spiky_proxy, [70, 72, 1600]), 80, "active", 1.0
        )
        steady = RankedTelegram(
            steady_proxy, good_result(steady_proxy, [100, 102, 105]), 80, "active", 1.0
        )
        self.assertEqual(
            fastest_proxies([spiky, steady], 2)[0].proxy.fingerprint, steady_proxy.fingerprint
        )

    def test_message_targets_require_clean_faketls_on_port_443(self) -> None:
        preferred = []
        for host in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            proxy = parse_proxy_url(proxy_url(secret=EE_SECRET, host=host))
            preferred.append(RankedTelegram(proxy, good_result(proxy), 90, "active", 1.0))
        raw = parse_proxy_url(proxy_url(secret=RAW_SECRET, port=22))
        raw_item = RankedTelegram(raw, good_result(raw, [40, 41, 42]), 99, "active", 1.0)

        first = select_message_targets([raw_item, *preferred], preferred, [raw_item, *preferred], 0)
        second = select_message_targets(
            [raw_item, *preferred], preferred, [raw_item, *preferred], 1
        )

        self.assertTrue(all(item["url"].endswith(EE_SECRET) for item in first.values()))
        self.assertNotEqual(first["fastest"]["url"], second["fastest"]["url"])

    def test_repeated_valid_zero_runs_eventually_replace_stale_data(self) -> None:
        previous = {"production": {"working": 80}, "suspicious_streak": 0}
        for expected_streak in (1, 2):
            healthy, reason, streak = assess_run(
                previous,
                successful_sources=4,
                expected=300,
                completed=300,
                working=0,
                control_ok=True,
                collapse_ratio=0.1,
                hold_runs=2,
            )
            self.assertFalse(healthy)
            self.assertEqual(reason, "MASS_FAILURE")
            self.assertEqual(streak, expected_streak)
            previous["suspicious_streak"] = streak
        healthy, reason, streak = assess_run(
            previous,
            successful_sources=4,
            expected=300,
            completed=300,
            working=0,
            control_ok=True,
            collapse_ratio=0.1,
            hold_runs=2,
        )
        self.assertTrue(healthy)
        self.assertIsNone(reason)
        self.assertEqual(streak, 0)


class TelegramPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_suspicious_zero_run_preserves_previous_files(self) -> None:
        source = SourceSpec("source", "source", "https://example.com/feed", {"telegram"})
        settings = {
            "telegram": {
                "paths": {
                    "history": "data/telegram-history.json",
                    "status": "Telegram/status.json",
                },
                "collection": {"fetch_timeout": 1},
                "testing": {"candidate_limit": 10},
                "history": {"window": 24, "promotion_runs": 3, "remove_failures": 3},
                "limits": {"stable": 50, "fastest": 20},
                "quality": {"stable_min_score": 65},
                "failure": {"collapse_ratio": 0.1, "hold_runs": 2},
                "sources": [{"id": source.source_id, "name": source.name, "url": source.url}],
            }
        }

        async def fake_fetch(*args: object, **kwargs: object) -> list[SourceResult]:
            return [SourceResult(source, proxy_url())]

        async def fake_resolve(
            proxies: list[TelegramProxy],
        ) -> tuple[list[TelegramProxy], dict[str, str]]:
            return proxies, {}

        async def fake_test(
            proxies: list[TelegramProxy], testing: dict[str, object]
        ) -> list[TelegramResult]:
            return [
                TelegramResult(proxy.fingerprint, "2026-08-28T13:00:00Z", attempts=3)
                for proxy in proxies
            ]

        async def fake_control(testing: dict[str, object]) -> bool:
            return True

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Telegram").mkdir()
            for name in ("all.txt", "stable.txt", "fastest.txt"):
                (root / "Telegram" / name).write_text(proxy_url() + "\n")
            (root / "Telegram/status.json").write_text(
                json.dumps(
                    {
                        "healthy_run": True,
                        "working": 1,
                        "production": {"working": 1, "stable": 1, "fastest": 1},
                        "suspicious_streak": 0,
                    }
                )
            )
            with (
                patch("swiftproxy.telegram_main.fetch_sources", fake_fetch),
                patch("swiftproxy.telegram_main.resolve_proxies", fake_resolve),
                patch("swiftproxy.telegram_main.test_proxies", fake_test),
                patch("swiftproxy.telegram_main.telegram_control", fake_control),
            ):
                exit_code = await run(root, settings)
            self.assertEqual(exit_code, 2)
            self.assertEqual((root / "Telegram/all.txt").read_text(), proxy_url() + "\n")
            status = json.loads((root / "Telegram/status.json").read_text())
            self.assertFalse(status["healthy_run"])
            self.assertEqual(status["failure_reason"], "MASS_FAILURE")


class TelegramPublisherTests(unittest.TestCase):
    def test_working_message_uses_swift_format(self) -> None:
        text, _ = message_payload(
            {
                "healthy_run": True,
                "working": 252,
                "tested": 357,
                "stable": 50,
                "updated_at": "2026-08-28T21:10:00Z",
            }
        )
        self.assertIn("<b>Swift · Telegram</b>", text)
        self.assertIn("<b>252</b> of <b>357</b> proxies passed", text)
        self.assertIn("<b>50</b> are stable", text)
        self.assertIn("29.08.2026 · 00:10 MSK", text)
        self.assertIn("<i>Filter the garbage. Keep what works.</i>", text)

    def test_failed_message_distinguishes_checker_failure(self) -> None:
        text, markup = message_payload(
            {
                "healthy_run": False,
                "last_successful_set": "2026-08-28T21:10:00Z",
            }
        )
        self.assertIn("Latest proxy check failed", text)
        self.assertIn("previous verified set is being kept", text)
        self.assertIn("Last verified: 29.08.2026 · 00:10 MSK", text)
        self.assertEqual(markup, {"inline_keyboard": []})

    def test_dynamic_button_count(self) -> None:
        base = {
            "healthy_run": True,
            "working": 3,
            "tested": 10,
            "stable": 1,
            "fastest": 3,
            "updated_at": "2026-08-28T12:00:00Z",
        }
        urls = {
            name: {"url": proxy_url(secret=secret)}
            for name, secret in (
                ("fastest", RAW_SECRET),
                ("stable", DD_SECRET),
                ("backup", EE_SECRET),
            )
        }
        for count, rows, buttons in ((3, 2, 3), (2, 1, 2), (1, 1, 1)):
            status = dict(base)
            status["selected"] = dict(list(urls.items())[:count])
            _, markup = message_payload(status)
            keyboard = markup["inline_keyboard"]
            self.assertEqual(len(keyboard), rows)
            self.assertEqual(sum(len(row) for row in keyboard), buttons)
        status = dict(base, selected={"fastest": urls["fastest"]})
        _, markup = message_payload(status)
        self.assertEqual(markup["inline_keyboard"][0][0]["text"], "Connect")

    def test_zero_proxy_message_has_no_buttons(self) -> None:
        text, markup = message_payload(
            {
                "healthy_run": True,
                "working": 0,
                "tested": 527,
                "last_successful_set": "2026-08-28T21:10:00Z",
            }
        )
        self.assertIn("No working proxies", text)
        self.assertIn("<b>0</b> of <b>527</b>", text)
        self.assertEqual(markup, {"inline_keyboard": []})

    def test_publishing_is_disabled_when_secrets_are_missing(self) -> None:
        self.assertFalse(publish_status({"healthy_run": True}, environ={}))

    def test_publisher_enables_html_formatting(self) -> None:
        requests = []

        class Response:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, limit: int) -> bytes:
                return b'{"ok": true}'

        def opener(request: object, timeout: int) -> Response:
            requests.append(request)
            return Response()

        published = publish_status(
            {"healthy_run": True, "working": 1, "tested": 1, "stable": 0},
            environ={
                "TELEGRAM_BOT_TOKEN": "synthetic-token",
                "TELEGRAM_CHAT_ID": "-100000000001",
                "TELEGRAM_MESSAGE_ID": "7",
            },
            opener=opener,
        )
        self.assertTrue(published)
        payload = json.loads(requests[0].data)
        self.assertEqual(payload["parse_mode"], "HTML")


if __name__ == "__main__":
    unittest.main()
