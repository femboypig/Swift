from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swiftproxy.models import ProxyConfig
from swiftproxy.parsing import parse_uri
from swiftproxy.ru_verify import (
    DownloadAttempt,
    RuVerifyResult,
    _verify_single,
    _curl_download,
    _probe_service_reachability,
    run_ru_verify,
)


class TestRuVerify(unittest.TestCase):
    def test_ru_verify_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_ru_verify_filters_blocked(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            line1 = "vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node1"
            line2 = "vless://b2222222-2222-2222-2222-222222222222@5.6.7.8:443?security=none#node2"
            main_file.write_text(f"{line1}\n{line2}\n")

            cfg1 = parse_uri(line1)
            cfg2 = parse_uri(line2)

            async def fake_verify(config, *args):
                if config.fingerprint == cfg1.fingerprint:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=True,
                        reason=None,
                        r1_kbps=150.0,
                        r2_kbps=140.0,
                        min_kbps=140.0,
                        https_passed=3,
                    )
                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=False,
                    reason="TOO_SLOW",
                    r1_kbps=40.0,
                    r2_kbps=30.0,
                    min_kbps=30.0,
                    https_passed=3,
                )

            mock_verify.side_effect = fake_verify

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            remaining = main_file.read_text().splitlines()
            self.assertEqual(len(remaining), 1)
            self.assertIn("node1", remaining[0])

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._probe_service_reachability", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_download", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_two_fast_downloads_pass(self, mock_probe, mock_dl, mock_svc, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        mock_probe.return_value = True
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.5, bytes_downloaded=262144, speed_kbps=170.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.6, bytes_downloaded=262144, speed_kbps=160.0),
        ]
        mock_svc.return_value = "reachable"

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertTrue(res.passed)
        self.assertIsNone(res.reason)
        self.assertEqual(res.min_kbps, 160.0)
        self.assertEqual(res.https_passed, 3)

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._curl_download", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_r1_fast_r2_stall_fails(self, mock_probe, mock_dl, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        mock_probe.return_value = True
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.5, bytes_downloaded=262144, speed_kbps=170.0),
            DownloadAttempt(ok=False, time_total=6.0, bytes_downloaded=20000, is_stall=True, error="Operation too slow"),
        ]

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertFalse(res.passed)
        self.assertEqual(res.reason, "STALLED")

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._curl_download", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_both_complete_but_too_slow_fails(self, mock_probe, mock_dl, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        mock_probe.return_value = True
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=5.0, bytes_downloaded=262144, speed_kbps=52.0),
            DownloadAttempt(ok=True, status_code=200, time_total=4.5, bytes_downloaded=262144, speed_kbps=58.0),
        ]

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertFalse(res.passed)
        self.assertEqual(res.reason, "TOO_SLOW")
        self.assertEqual(res.min_kbps, 52.0)

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_https_insufficient_fails(self, mock_probe, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        # only 1 of 3 passes
        mock_probe.side_effect = [True, False, False]

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertFalse(res.passed)
        self.assertEqual(res.reason, "HTTPS_FAILED")
        self.assertEqual(res.https_passed, 1)

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._probe_service_reachability", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_download", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_ozon_timeout_does_not_drop_generic_main_node(self, mock_probe, mock_dl, mock_svc, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        mock_probe.return_value = True
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=250.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.2, bytes_downloaded=262144, speed_kbps=210.0),
        ]
        
        async def fake_svc(port, url, *args, **kwargs):
            if "ozon" in url:
                return "unreachable" # Ozon timed out
            return "reachable"

        mock_svc.side_effect = fake_svc

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node_nl")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem, country="NL"))

        # Core test passed -> Node passes generic Main!
        self.assertTrue(res.passed)
        self.assertEqual(res.services.get("ozon"), "unreachable")
        self.assertIsNone(res.ru_service_ok) # country is NL

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._probe_service_reachability", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_download", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_ru_egress_service_classification(self, mock_probe, mock_dl, mock_svc, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        mock_probe.return_value = True
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
        ]

        # Case 1: Yandex OK, VK OK, Ozon FAIL -> ru_service_ok = True
        mock_svc.side_effect = lambda port, url, *args, **kwargs: "unreachable" if "ozon" in url else "reachable"
        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node_ru")
        sem = asyncio.Semaphore(1)
        res1 = asyncio.run(_verify_single(cfg, "sing-box", sem, country="RU"))
        self.assertTrue(res1.passed)
        self.assertTrue(res1.ru_service_ok)

        # Case 2: Yandex FAIL, VK OK, Ozon OK -> ru_service_ok = False
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
        ]
        mock_svc.side_effect = lambda port, url, *args, **kwargs: "unreachable" if "yandex" in url else "reachable"
        res2 = asyncio.run(_verify_single(cfg, "sing-box", sem, country="RU"))
        self.assertTrue(res2.passed) # generic Main pass
        self.assertFalse(res2.ru_service_ok) # RU service failed

    @patch("asyncio.create_subprocess_exec")
    def test_http_403_counted_as_reachable(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.returncode = 0
        proc_mock.communicate.return_value = (b"403", b"")
        mock_exec.return_value = proc_mock

        status = asyncio.run(_probe_service_reachability(1080, "https://ozon.ru"))
        self.assertEqual(status, "reachable")

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    def test_infrastructure_failure_marked_separately(self, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = False # core timed out
        mock_exec.return_value = AsyncMock()

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertFalse(res.passed)
        self.assertTrue(res.is_infrastructure_failure)
        self.assertEqual(res.reason, "CORE_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
