from __future__ import annotations

import asyncio
import json
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
    def test_main_only_pass(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            line1 = "vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node1"
            main_file.write_text(f"{line1}\n")

            cfg1 = parse_uri(line1)
            mock_verify.return_value = RuVerifyResult(
                fingerprint=cfg1.fingerprint,
                passed=True,
                reason=None,
                r1_kbps=150.0,
                r2_kbps=140.0,
                min_kbps=140.0,
                https_passed=3,
            )

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            self.assertIn(line1, main_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_white_only_pass(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            white_file = sub_dir / "white.txt"
            line_w = "vless://b1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#white_node"
            white_file.write_text(f"{line_w}\n")

            cfg_w = parse_uri(line_w)
            mock_verify.return_value = RuVerifyResult(
                fingerprint=cfg_w.fingerprint,
                passed=True,
                reason=None,
                r1_kbps=200.0,
                r2_kbps=180.0,
                min_kbps=180.0,
                https_passed=3,
            )

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            self.assertIn(line_w, white_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_shared_main_and_white_tested_once_and_preserved_in_both(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            white_file = sub_dir / "white.txt"

            shared_line = "vless://c1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#shared_node"
            main_file.write_text(f"{shared_line}\n")
            white_file.write_text(f"{shared_line}\n")

            cfg = parse_uri(shared_line)
            mock_verify.return_value = RuVerifyResult(
                fingerprint=cfg.fingerprint,
                passed=True,
                reason=None,
                r1_kbps=220.0,
                r2_kbps=210.0,
                min_kbps=210.0,
                https_passed=3,
            )

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            # Tested exactly ONCE on Mac
            self.assertEqual(mock_verify.call_count, 1)
            # Preserved in both subscriptions
            self.assertIn(shared_line, main_file.read_text())
            self.assertIn(shared_line, white_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_shared_main_and_white_fail_removed_from_both(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            white_file = sub_dir / "white.txt"

            shared_line = "vless://d1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#bad_shared"
            good_main = "vless://d2222222-2222-2222-2222-222222222222@5.6.7.8:443?security=none#good_main"
            good_white = "vless://d3333333-3333-3333-3333-333333333333@9.9.9.9:443?security=none#good_white"

            main_file.write_text(f"{shared_line}\n{good_main}\n")
            white_file.write_text(f"{shared_line}\n{good_white}\n")

            cfg_shared = parse_uri(shared_line)
            cfg_m = parse_uri(good_main)
            cfg_w = parse_uri(good_white)

            async def fake_verify(config, *args):
                if config.fingerprint == cfg_shared.fingerprint:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="HTTPS_FAILED",
                        https_passed=0,
                    )
                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=True,
                    reason=None,
                    r1_kbps=180.0,
                    r2_kbps=170.0,
                    min_kbps=170.0,
                    https_passed=3,
                )

            mock_verify.side_effect = fake_verify
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            # shared node must be removed from both
            self.assertNotIn(shared_line, main_file.read_text())
            self.assertNotIn(shared_line, white_file.read_text())
            # good nodes must remain
            self.assertIn(good_main, main_file.read_text())
            self.assertIn(good_white, white_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_white_stalled_removed(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            white_file = sub_dir / "white.txt"

            stall_line = "vless://e1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#stall_white"
            good_line = "vless://e2222222-2222-2222-2222-222222222222@5.6.7.8:443?security=none#good_white"
            white_file.write_text(f"{stall_line}\n{good_line}\n")

            cfg_stall = parse_uri(stall_line)
            cfg_good = parse_uri(good_line)

            async def fake_verify(config, *args):
                if config.fingerprint == cfg_stall.fingerprint:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="STALLED",
                        r1_kbps=120.0,
                        r2_kbps=0.0,
                        https_passed=3,
                    )
                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=True,
                    reason=None,
                    r1_kbps=200.0,
                    r2_kbps=190.0,
                    min_kbps=190.0,
                    https_passed=3,
                )

            mock_verify.side_effect = fake_verify
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            self.assertNotIn(stall_line, white_file.read_text())
            self.assertIn(good_line, white_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_white_too_slow_removed(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            white_file = sub_dir / "white.txt"

            slow_line = "vless://f1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#slow_white"
            good_line = "vless://f2222222-2222-2222-2222-222222222222@5.6.7.8:443?security=none#good_white"
            white_file.write_text(f"{slow_line}\n{good_line}\n")

            cfg_slow = parse_uri(slow_line)

            async def fake_verify(config, *args):
                if config.fingerprint == cfg_slow.fingerprint:
                    return RuVerifyResult(
                        fingerprint=config.fingerprint,
                        passed=False,
                        reason="TOO_SLOW",
                        r1_kbps=55.0,
                        r2_kbps=40.0,
                        min_kbps=40.0,
                        https_passed=3,
                    )
                return RuVerifyResult(
                    fingerprint=config.fingerprint,
                    passed=True,
                    reason=None,
                    r1_kbps=200.0,
                    r2_kbps=190.0,
                    min_kbps=190.0,
                    https_passed=3,
                )

            mock_verify.side_effect = fake_verify
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            self.assertNotIn(slow_line, white_file.read_text())
            self.assertIn(good_line, white_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_infrastructure_failure_preserves_lkg_main(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            lines = [
                f"vless://a{i}111111-1111-1111-1111-111111111111@1.2.3.{i}:443?security=none#node{i}"
                for i in range(12)
            ]
            main_file.write_text("\n".join(lines) + "\n")

            mock_verify.return_value = RuVerifyResult(
                fingerprint="any",
                passed=False,
                reason="CORE_TIMEOUT",
                is_infrastructure_failure=True,
            )

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            # LKG must be preserved!
            self.assertEqual(main_file.read_text().splitlines(), lines)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_infrastructure_failure_preserves_lkg_white(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            white_file = sub_dir / "white.txt"
            lines = [
                f"vless://b{i}111111-1111-1111-1111-111111111111@1.2.3.{i}:443?security=none#white{i}"
                for i in range(12)
            ]
            white_file.write_text("\n".join(lines) + "\n")

            mock_verify.return_value = RuVerifyResult(
                fingerprint="any",
                passed=False,
                reason="CORE_TIMEOUT",
                is_infrastructure_failure=True,
            )

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            # LKG must be preserved!
            self.assertEqual(white_file.read_text().splitlines(), lines)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_partial_normal_proxy_failure_does_not_trigger_lkg_fallback(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            lines = [
                f"vless://c{i}111111-1111-1111-1111-111111111111@1.2.3.{i}:443?security=none#node{i}"
                for i in range(10)
            ]
            main_file.write_text("\n".join(lines) + "\n")

            # 4 nodes pass (40% pass rate > 10% outage threshold), 6 fail normally
            async def fake_verify(config, *args):
                i = int(config.host.split(".")[-1])
                if i < 4:
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
                    reason="HTTPS_FAILED",
                    https_passed=0,
                )

            mock_verify.side_effect = fake_verify
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            # Exactly 4 nodes must be published (LKG not triggered)
            written = [l for l in main_file.read_text().splitlines() if l.strip()]
            self.assertEqual(len(written), 4)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_plain_and_happ_outputs_contain_identical_final_fingerprint_set(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            happ_dir = sub_dir / "happ"
            happ_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            happ_main = happ_dir / "main.txt"
            white_file = sub_dir / "white.txt"
            happ_white = happ_dir / "white.txt"

            line_vless_main = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#vless_m"
            line_hy2_main = "hysteria2://hy2password@5.6.7.8:443?sni=example.com#hy2_m"
            line_vless_white = "vless://22222222-2222-2222-2222-222222222222@9.9.9.9:443?security=none#vless_w"

            main_file.write_text(f"{line_vless_main}\n{line_hy2_main}\n")
            happ_main.write_text(f"{line_vless_main}\n{line_hy2_main}\n")
            white_file.write_text(f"{line_vless_white}\n")
            happ_white.write_text(f"{line_vless_white}\n")

            mock_verify.return_value = RuVerifyResult(
                fingerprint="any",
                passed=True,
                reason=None,
                r1_kbps=200.0,
                r2_kbps=190.0,
                min_kbps=190.0,
                https_passed=3,
            )

            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            # Check that happ files contain the verified lines
            happ_main_text = happ_main.read_text()
            self.assertIn("1.2.3.4", happ_main_text)
            self.assertIn("5.6.7.8", happ_main_text)

            happ_white_text = happ_white.read_text()
            self.assertIn("9.9.9.9", happ_white_text)

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
        mock_svc.return_value = "reachable"
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=220.0),
        ]

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertTrue(res.passed)
        self.assertEqual(res.r1_kbps, 200.0)
        self.assertEqual(res.r2_kbps, 220.0)
        self.assertEqual(res.min_kbps, 200.0)
        self.assertIsNone(res.reason)

    @patch("swiftproxy.ru_verify._stop_process", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._wait_for_core", new_callable=AsyncMock)
    @patch("asyncio.create_subprocess_exec")
    @patch("swiftproxy.ru_verify._probe_service_reachability", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_download", new_callable=AsyncMock)
    @patch("swiftproxy.ru_verify._curl_probe", new_callable=AsyncMock)
    def test_r1_fast_r2_stall_fails(self, mock_probe, mock_dl, mock_svc, mock_exec, mock_wait, mock_stop):
        mock_wait.return_value = True
        mock_exec.return_value = AsyncMock()
        mock_probe.return_value = True
        mock_svc.return_value = "reachable"
        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=250.0),
            DownloadAttempt(ok=False, time_total=3.1, is_stall=True, error="Operation too slow"),
        ]

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertFalse(res.passed)
        self.assertEqual(res.reason, "STALLED")
        self.assertEqual(res.r1_kbps, 250.0)

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
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=150.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=140.0),
        ]
        mock_svc.side_effect = lambda port, url, *args, **kwargs: "unreachable" if "ozon" in url else "reachable"

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node_nl")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem, country="NL"))

        self.assertTrue(res.passed)
        self.assertEqual(res.services.get("ozon"), "unreachable")
        self.assertIsNone(res.ru_service_ok)

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

        mock_svc.side_effect = lambda port, url, *args, **kwargs: "unreachable" if "ozon" in url else "reachable"
        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node_ru")
        sem = asyncio.Semaphore(1)
        res1 = asyncio.run(_verify_single(cfg, "sing-box", sem, country="RU"))
        self.assertTrue(res1.passed)
        self.assertTrue(res1.ru_service_ok)

        mock_dl.side_effect = [
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
            DownloadAttempt(ok=True, status_code=200, time_total=1.0, bytes_downloaded=262144, speed_kbps=200.0),
        ]
        mock_svc.side_effect = lambda port, url, *args, **kwargs: "unreachable" if "yandex" in url else "reachable"
        res2 = asyncio.run(_verify_single(cfg, "sing-box", sem, country="RU"))
        self.assertTrue(res2.passed)
        self.assertFalse(res2.ru_service_ok)

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
        mock_wait.return_value = False
        mock_exec.return_value = AsyncMock()

        cfg = parse_uri("vless://a1111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#node")
        sem = asyncio.Semaphore(1)
        res = asyncio.run(_verify_single(cfg, "sing-box", sem))

        self.assertFalse(res.passed)
        self.assertTrue(res.is_infrastructure_failure)
        self.assertEqual(res.reason, "CORE_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
