from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swiftproxy.models import ProxyConfig, RankedConfig, TestResult
from swiftproxy.output import check_outputs
from swiftproxy.parsing import parse_uri
from swiftproxy.ru_verify import RuVerifyResult, run_ru_verify
from swiftproxy.scoring import diverse_selection, select_pre_mac_candidates


def _dummy_ranked_config(
    fingerprint_suffix: str,
    score: float = 75.0,
    state: str = "active",
    country: str = "NL",
    asn: int = 12345,
    host: str = "140.82.33.78",
    port: int = 443,
    lane: str = "main",
) -> RankedConfig:
    cfg = ProxyConfig(
        protocol="vless",
        host=host,
        port=port,
        auth={"uuid": f"00000000-0000-0000-0000-{fingerprint_suffix.zfill(12)}"},
        remark=f"node_{fingerprint_suffix}",
    )
    result = TestResult(
        fingerprint=cfg.fingerprint,
        lane=lane,
        timestamp="2026-08-31T00:00:00Z",
        success_count=2,
        rounds_attempted=2,
        rounds_succeeded=2,
        throughput_bps=300_000.0,
        median_latency_ms=150.0,
        country=country,
        asn=asn,
    )
    return RankedConfig(
        config=cfg,
        lane=lane,
        result=result,
        score=score,
        state=state,
        availability=1.0,
    )


class TestPostMacFinalSelection(unittest.TestCase):
    def test_eligible_50_all_sent_to_mac(self):
        eligible = [_dummy_ranked_config(str(i), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000) for i in range(50)]
        history = {"version": 3, "configs": {}}
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed1", history)
        self.assertEqual(len(pre_mac), 50)
        self.assertEqual(pre_mac, eligible)

    def test_eligible_200_all_sent_to_mac(self):
        eligible = [_dummy_ranked_config(str(i), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000) for i in range(200)]
        history = {"version": 3, "configs": {}}
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed1", history)
        self.assertEqual(len(pre_mac), 200)

    def test_eligible_299_all_sent_to_mac(self):
        eligible = [_dummy_ranked_config(str(i), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000) for i in range(299)]
        history = {"version": 3, "configs": {}}
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed1", history)
        self.assertEqual(len(pre_mac), 299)

    def test_eligible_300_all_sent_to_mac(self):
        eligible = [_dummy_ranked_config(str(i), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000) for i in range(300)]
        history = {"version": 3, "configs": {}}
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed1", history)
        self.assertEqual(len(pre_mac), 300)

    def test_eligible_301_safety_selection_returns_exactly_300(self):
        eligible = [_dummy_ranked_config(str(i), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000) for i in range(301)]
        history = {"version": 3, "configs": {}}
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed1", history)
        self.assertEqual(len(pre_mac), 300)

    def test_eligible_450_safety_selection_returns_exactly_300(self):
        eligible = [_dummy_ranked_config(str(i), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000) for i in range(450)]
        history = {"version": 3, "configs": {}}
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed1", history)
        self.assertEqual(len(pre_mac), 300)

    def test_working_veteran_with_old_rank_gt_200_not_lost_when_eligible_le_300(self):
        eligible = [
            _dummy_ranked_config(f"cfg_{i}", score=90.0 - (i * 0.05), host=f"140.82.{i // 250}.{i % 250 + 1}", port=i + 1000)
            for i in range(250)
        ]
        veteran = eligible[230]
        history = {
            "version": 3,
            "configs": {
                veteran.config.fingerprint: {
                    "lanes": {"main": {"state": "active", "score": 78.5, "observations": [{"success": True}]}}
                }
            },
        }
        pre_mac = select_pre_mac_candidates(eligible, 300, "seed_test", history)
        self.assertEqual(len(pre_mac), 250)
        self.assertIn(veteran, pre_mac)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_veteran_mac_fail_is_never_published(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            
            veteran_line = "vless://00000000-0000-0000-0000-111111111111@140.82.33.78:443?security=none#veteran_node"
            main_file.write_text(f"{veteran_line}\n")
            
            cfg = parse_uri(veteran_line)
            mock_verify.return_value = RuVerifyResult(
                fingerprint=cfg.fingerprint,
                passed=False,
                reason="HTTPS_FAILED",
                r1_kbps=0.0,
                r2_kbps=0.0,
                min_kbps=0.0,
                https_passed=0,
            )
            
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            self.assertEqual(main_file.read_text().strip(), "")

    @patch("swiftproxy.ru_verify._verify_single")
    def test_new_config_mac_pass_can_reach_final(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            
            new_line = "vless://00000000-0000-0000-0000-222222222222@140.82.33.79:443?security=none#new_node"
            main_file.write_text(f"{new_line}\n")
            
            cfg = parse_uri(new_line)
            mock_verify.return_value = RuVerifyResult(
                fingerprint=cfg.fingerprint,
                passed=True,
                reason=None,
                r1_kbps=180.0,
                r2_kbps=190.0,
                min_kbps=180.0,
                https_passed=3,
            )
            
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            self.assertIn(new_line, main_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_more_than_80_mac_pass_caps_at_exactly_80(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            
            # Write 100 passing candidates with unique hosts
            lines = [
                f"vless://00000000-0000-0000-0000-{str(i).zfill(12)}@140.82.{i // 250}.{i % 250 + 1}:{1000 + i}?security=none#node_{i}"
                for i in range(100)
            ]
            main_file.write_text("\n".join(lines) + "\n")
            
            async def mock_fn(cfg, *args, **kwargs):
                return RuVerifyResult(
                    fingerprint=cfg.fingerprint,
                    passed=True,
                    reason=None,
                    r1_kbps=200.0,
                    r2_kbps=200.0,
                    min_kbps=200.0,
                    https_passed=3,
                )
            
            mock_verify.side_effect = mock_fn
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            
            published_lines = [l for l in main_file.read_text().splitlines() if l.strip()]
            self.assertEqual(len(published_lines), 80)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_less_than_80_mac_pass_publishes_all_passed(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            
            lines = [
                f"vless://00000000-0000-0000-0000-{str(i).zfill(12)}@140.82.{i // 250}.{i % 250 + 1}:{1000 + i}?security=none#node_{i}"
                for i in range(25)
            ]
            main_file.write_text("\n".join(lines) + "\n")
            
            # 6 pass, 19 fail
            async def mock_fn(cfg, *args, **kwargs):
                idx = int(cfg.remark.split("_")[-1])
                passed = idx < 6
                return RuVerifyResult(
                    fingerprint=cfg.fingerprint,
                    passed=passed,
                    reason=None if passed else "HTTPS_FAILED",
                    r1_kbps=200.0 if passed else 0.0,
                    r2_kbps=200.0 if passed else 0.0,
                    min_kbps=200.0 if passed else 0.0,
                    https_passed=3 if passed else 0,
                )
            
            mock_verify.side_effect = mock_fn
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            
            published_lines = [l for l in main_file.read_text().splitlines() if l.strip()]
            self.assertEqual(len(published_lines), 6)

    @patch("swiftproxy.ru_verify._verify_single")
    def test_shared_main_and_white_tested_once(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            white_file = sub_dir / "white.txt"
            
            shared = "vless://00000000-0000-0000-0000-999999999999@140.82.33.78:443?security=none#shared"
            main_file.write_text(f"{shared}\n")
            white_file.write_text(f"{shared}\n")
            
            cfg = parse_uri(shared)
            mock_verify.return_value = RuVerifyResult(
                fingerprint=cfg.fingerprint,
                passed=True,
                reason=None,
                r1_kbps=200.0,
                r2_kbps=200.0,
                min_kbps=200.0,
                https_passed=3,
            )
            
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)
            self.assertEqual(mock_verify.call_count, 1)
            self.assertIn(shared, main_file.read_text())
            self.assertIn(shared, white_file.read_text())

    @patch("swiftproxy.ru_verify._verify_single")
    def test_lkg_protection_on_infra_failure(self, mock_verify):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sub_dir = root / "sub"
            sub_dir.mkdir(parents=True)
            main_file = sub_dir / "main.txt"
            
            lines = [
                f"vless://00000000-0000-0000-0000-{str(i).zfill(12)}@140.82.{i // 250}.{i % 250 + 1}:{1000 + i}?security=none#node_{i}"
                for i in range(12)
            ]
            main_file.write_text("\n".join(lines) + "\n")
            
            async def mock_fn(cfg, *args, **kwargs):
                return RuVerifyResult(
                    fingerprint=cfg.fingerprint,
                    passed=False,
                    reason="INFRA_TIMEOUT",
                    is_infrastructure_failure=True,
                )
            
            mock_verify.side_effect = mock_fn
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
