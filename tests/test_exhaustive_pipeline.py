import asyncio
import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swiftproxy.models import ProxyConfig, RankedConfig, TestResult
from swiftproxy.main import _cloud_lane_counts, _jobs, _tcp_tls_telemetry_counts
from swiftproxy.output import write_final_subscriptions
from swiftproxy.parsing import parse_uri, serialize_uri
from swiftproxy.ru_verify import MacPreflightResult, RuVerifyResult, run_ru_verify
from swiftproxy.scoring import choose_candidates, select_pre_mac_candidates, diverse_selection


import hashlib


def _make_config(
    fp: str,
    lane: str | list[str] = "main",
    host: str = "1.1.1.1",
    port: int = 443,
    proto: str = "vless",
) -> ProxyConfig:
    lanes_set = {lane} if isinstance(lane, str) else set(lane)
    h = hashlib.md5(fp.encode()).hexdigest()
    uuid_str = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    return ProxyConfig(
        protocol=proto,
        host=host,
        port=port,
        auth={"uuid": uuid_str},
        options={"security": "reality", "sni": "example.com", "public_key": "abc", "short_id": ""}
        if proto == "vless"
        else {},
        sources={"test"},
        lanes=lanes_set,
        remark=f"test_{fp}",
    )


class TestExhaustiveValidationPipeline(unittest.TestCase):
    """
    Test suite verifying the 20 architectural invariants of Exhaustive Validation:
    - No selection caps before Cloud or Mac stages
    - Exhaustive candidate scheduling
    - Mac PASS requirement for publication
    - White tcp_tls telemetry-only decoupling
    - Shared Main+White single-test reuse
    - Incomplete run detection & LKG protection
    """

    # 1. 50 unique Main -> all 50 scheduled for Cloud
    def test_01_50_unique_main_all_scheduled(self):
        configs = [_make_config(str(i), lane="main") for i in range(50)]
        scheduled = choose_candidates(configs, {}, "main", limit=None)
        self.assertEqual(len(scheduled), 50)

    def test_cloud_jobs_interleave_lanes_without_dropping_work(self):
        main = [_make_config(f"main-{index}", lane="main") for index in range(4)]
        white = [_make_config(f"white-{index}", lane="white") for index in range(2)]
        jobs = _jobs(
            {"main": main, "white": white},
            {config.fingerprint for config in [*main, *white]},
        )

        self.assertEqual(
            [lane for _, lane in jobs], ["main", "white", "main", "white", "main", "main"]
        )
        self.assertEqual(len(jobs), 6)
        self.assertEqual(len({(config.fingerprint, lane) for config, lane in jobs}), 6)

    # 2. 1000 unique Main -> all 1000 scheduled for Cloud
    def test_02_1000_unique_main_all_scheduled(self):
        configs = [_make_config(str(i), lane="main") for i in range(1000)]
        scheduled = choose_candidates(configs, {}, "main", limit=None)
        self.assertEqual(len(scheduled), 1000)

    # 3. 6961 unique Main -> all 6961 are scheduled for Cloud
    def test_03_6961_unique_main_all_scheduled(self):
        configs = [_make_config(str(i), lane="main") for i in range(6961)]
        scheduled = choose_candidates(configs, {}, "main", limit=None)
        self.assertEqual(len(scheduled), 6961)

    # 4. No hidden [:N] / selection cap truncates Main Cloud population
    def test_04_no_hidden_cloud_selection_cap(self):
        configs = [_make_config(str(i), lane="main") for i in range(2500)]
        scheduled_zero = choose_candidates(configs, {}, "main", limit=0)
        scheduled_none = choose_candidates(configs, {}, "main", limit=None)
        self.assertEqual(len(scheduled_zero), 2500)
        self.assertEqual(len(scheduled_none), 2500)

    # 5. 50 history-eligible Main -> all 50 sent to Mac
    def test_05_50_eligible_all_sent_to_mac(self):
        eligible = [
            RankedConfig(
                config=_make_config(str(i), lane="main"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0,
                state="active",
                availability=1.0,
            )
            for i in range(50)
        ]
        pre_mac = select_pre_mac_candidates(eligible, limit=None)
        self.assertEqual(len(pre_mac), 50)

    # 6. 300 eligible -> all 300 sent
    def test_06_300_eligible_all_sent(self):
        eligible = [
            RankedConfig(
                config=_make_config(str(i), lane="main"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0,
                state="active",
                availability=1.0,
            )
            for i in range(300)
        ]
        pre_mac = select_pre_mac_candidates(eligible, limit=None)
        self.assertEqual(len(pre_mac), 300)

    # 7. 301 eligible -> all 301 sent
    def test_07_301_eligible_all_sent(self):
        eligible = [
            RankedConfig(
                config=_make_config(str(i), lane="main"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0,
                state="active",
                availability=1.0,
            )
            for i in range(301)
        ]
        pre_mac = select_pre_mac_candidates(eligible, limit=None)
        self.assertEqual(len(pre_mac), 301)

    # 8. 520 eligible -> all 520 sent
    def test_08_520_eligible_all_sent(self):
        eligible = [
            RankedConfig(
                config=_make_config(str(i), lane="main"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0,
                state="active",
                availability=1.0,
            )
            for i in range(520)
        ]
        pre_mac = select_pre_mac_candidates(eligible, limit=None)
        self.assertEqual(len(pre_mac), 520)

    # 9. No hidden mac_candidates truncation
    def test_09_no_hidden_mac_candidates_truncation(self):
        eligible = [
            RankedConfig(
                config=_make_config(str(i), lane="main"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0,
                state="active",
                availability=1.0,
            )
            for i in range(800)
        ]
        pre_mac_zero = select_pre_mac_candidates(eligible, limit=0)
        pre_mac_none = select_pre_mac_candidates(eligible, limit=None)
        self.assertEqual(len(pre_mac_zero), 800)
        self.assertEqual(len(pre_mac_none), 800)

    # 10. 20 Mac PASS -> publish 20
    def test_10_20_mac_pass_publishes_20(self):
        passed = [
            RankedConfig(
                config=_make_config(str(i), lane="main", host=f"10.0.{i}.1"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0 - i * 0.1,
                state="active",
                availability=1.0,
            )
            for i in range(20)
        ]
        final = diverse_selection(passed, limit=80, endpoint_limit=3, subnet_limit=6, asn_limit=12)
        self.assertEqual(len(final), 20)

    # 11. 80 Mac PASS -> publish 80
    def test_11_80_mac_pass_publishes_80(self):
        passed = [
            RankedConfig(
                config=_make_config(str(i), lane="main", host=f"10.{i // 256}.{i % 256}.1"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=80.0 - i * 0.1,
                state="active",
                availability=1.0,
            )
            for i in range(80)
        ]
        final = diverse_selection(passed, limit=80, endpoint_limit=3, subnet_limit=6, asn_limit=12)
        self.assertEqual(len(final), 80)

    # 12. 81 Mac PASS -> publish exactly best 80
    def test_12_81_mac_pass_publishes_best_80(self):
        passed = [
            RankedConfig(
                config=_make_config(str(i), lane="main", host=f"10.{i // 256}.{i % 256}.1"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=90.0 - i * 0.1,
                state="active",
                availability=1.0,
            )
            for i in range(81)
        ]
        final = diverse_selection(passed, limit=80, endpoint_limit=3, subnet_limit=6, asn_limit=12)
        self.assertEqual(len(final), 80)
        fps = {item.config.fingerprint for item in final}
        self.assertNotIn(_make_config("80").fingerprint, fps)

    # 13. 200 Mac PASS -> publish exactly best 80
    def test_13_200_mac_pass_publishes_best_80(self):
        passed = [
            RankedConfig(
                config=_make_config(str(i), lane="main", host=f"10.{i // 256}.{i % 256}.1"),
                lane="main",
                result=TestResult(
                    _make_config(str(i)).fingerprint,
                    "main",
                    "2026-08-31T00:00:00Z",
                    success_count=1,
                ),
                score=90.0 - i * 0.1,
                state="active",
                availability=1.0,
            )
            for i in range(200)
        ]
        final = diverse_selection(passed, limit=80, endpoint_limit=3, subnet_limit=6, asn_limit=12)
        self.assertEqual(len(final), 80)

    # 14. Mac FAIL can never be published
    def test_14_mac_fail_is_never_published(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            main_cfg = _make_config("fail1", lane="main")
            from swiftproxy.parsing import serialize_uri

            (root / "sub/main.txt").write_text(serialize_uri(main_cfg) + "\n")
            (root / "data/order.json").write_text(json.dumps({"main": []}))
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                    }
                )
            )

            async def fake_verify_single(cfg, *args, **kwargs):
                return RuVerifyResult(cfg.fingerprint, passed=False, reason="HTTPS_FAILED")

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                ru_verify_main(["--root", str(root), "--core", str(core)])

            published = (root / "sub/main.txt").read_text().strip()
            self.assertEqual(published, "")

    # 15. White tcp_tls FAIL + Mac PASS -> CAN be published
    def test_15_white_tcp_tls_fail_mac_pass_is_published(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            from swiftproxy.parsing import serialize_uri, parse_uri

            white_cfg = _make_config("w_pass1", lane="white", proto="vless")
            parsed_cfg = parse_uri(serialize_uri(white_cfg))
            (root / "sub/white.txt").write_text(serialize_uri(white_cfg) + "\n")
            (root / "data/order.json").write_text(json.dumps({"white": []}))
            (root / "data/ru_probe_white.json").write_text(
                json.dumps({parsed_cfg.fingerprint: "fail"})
            )
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                    }
                )
            )

            async def fake_verify_single(cfg, *args, **kwargs):
                return RuVerifyResult(
                    cfg.fingerprint, passed=True, r1_kbps=150.0, r2_kbps=160.0, https_passed=3
                )

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                ru_verify_main(["--root", str(root), "--core", str(core)])

            published = (root / "sub/white.txt").read_text().strip()
            self.assertTrue(len(published) > 0)
            stats = json.loads((root / "stats.json").read_text())
            matrix = stats.get("telemetry", {}).get("white_tcp_tls_matrix", {})
            self.assertEqual(matrix.get("tcp_tls_fail__mac_pass"), 1)

    # 16. White tcp_tls PASS + Mac FAIL -> cannot be published
    def test_16_white_tcp_tls_pass_mac_fail_is_not_published(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            from swiftproxy.parsing import serialize_uri, parse_uri

            white_cfg = _make_config("w_fail1", lane="white", proto="vless")
            parsed_cfg = parse_uri(serialize_uri(white_cfg))
            (root / "sub/white.txt").write_text(serialize_uri(white_cfg) + "\n")
            (root / "data/order.json").write_text(json.dumps({"white": []}))
            (root / "data/ru_probe_white.json").write_text(
                json.dumps({parsed_cfg.fingerprint: "pass"})
            )
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                    }
                )
            )

            async def fake_verify_single(cfg, *args, **kwargs):
                return RuVerifyResult(cfg.fingerprint, passed=False, reason="HTTPS_FAILED")

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                ru_verify_main(["--root", str(root), "--core", str(core)])

            published = (root / "sub/white.txt").read_text().strip()
            self.assertEqual(published, "")
            stats = json.loads((root / "stats.json").read_text())
            matrix = stats.get("telemetry", {}).get("white_tcp_tls_matrix", {})
            self.assertEqual(matrix.get("tcp_tls_pass__mac_fail"), 1)

    # 17. White tcp_tls infrastructure failure does not block Mac validation
    def test_17_white_tcp_tls_infra_failure_does_not_block_mac(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            from swiftproxy.parsing import serialize_uri, parse_uri

            white_cfg = _make_config("w_infra1", lane="white", proto="vless")
            parsed_cfg = parse_uri(serialize_uri(white_cfg))
            (root / "sub/white.txt").write_text(serialize_uri(white_cfg) + "\n")
            (root / "data/order.json").write_text(json.dumps({"white": []}))
            (root / "data/ru_probe_white.json").write_text(
                json.dumps({parsed_cfg.fingerprint: "unknown"})
            )
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                    }
                )
            )

            async def fake_verify_single(cfg, *args, **kwargs):
                return RuVerifyResult(
                    cfg.fingerprint, passed=True, r1_kbps=150.0, r2_kbps=160.0, https_passed=3
                )

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                ru_verify_main(["--root", str(root), "--core", str(core)])

            published = (root / "sub/white.txt").read_text().strip()
            self.assertTrue(len(published) > 0)
            stats = json.loads((root / "stats.json").read_text())
            matrix = stats.get("telemetry", {}).get("white_tcp_tls_matrix", {})
            self.assertEqual(matrix.get("tcp_tls_unknown__mac_pass"), 1)

    # 18. Shared Main+White fingerprint is actual-traffic tested only once
    def test_18_shared_main_and_white_tested_only_once(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            from swiftproxy.parsing import serialize_uri, parse_uri

            cfg = _make_config("shared1", lane=["main", "white"], proto="vless")
            parsed_cfg = parse_uri(serialize_uri(cfg))
            (root / "sub/main.txt").write_text(serialize_uri(cfg) + "\n")
            (root / "sub/white.txt").write_text(serialize_uri(cfg) + "\n")
            (root / "data/order.json").write_text(json.dumps({"main": [], "white": []}))
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                    }
                )
            )

            test_calls = []

            async def fake_verify_single(config, *args, **kwargs):
                test_calls.append(config.fingerprint)
                return RuVerifyResult(
                    config.fingerprint, passed=True, r1_kbps=100.0, r2_kbps=100.0, https_passed=3
                )

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                ru_verify_main(["--root", str(root), "--core", str(core)])

            self.assertEqual(test_calls, [parsed_cfg.fingerprint])
            self.assertIn("test_shared1", (root / "sub/main.txt").read_text())
            self.assertIn("test_shared1", (root / "sub/white.txt").read_text())

    # 19. Incomplete exhaustive run is explicitly marked incomplete
    def test_19_incomplete_exhaustive_run_is_marked_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            from swiftproxy.parsing import serialize_uri, parse_uri

            cfg1 = _make_config("fp1", lane="main")
            cfg2 = _make_config("fp2", lane="main", host="1.0.0.1")
            parsed_1 = parse_uri(serialize_uri(cfg1))
            parsed_2 = parse_uri(serialize_uri(cfg2))
            (root / "sub/main.txt").write_text(f"{serialize_uri(cfg1)}\n{serialize_uri(cfg2)}\n")
            (root / "data/order.json").write_text(json.dumps({"main": []}))
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                        "funnel": {
                            "main": {
                                "main_cloud_expected": 2000,
                                "main_cloud_tested": 1500,
                                "main_cloud_untested": 500,
                            }
                        },
                    }
                )
            )

            async def fake_verify_single(cfg, *args, **kwargs):
                if cfg.fingerprint == parsed_1.fingerprint:
                    return RuVerifyResult(
                        parsed_1.fingerprint,
                        passed=True,
                        r1_kbps=100.0,
                        r2_kbps=100.0,
                        https_passed=3,
                    )
                return RuVerifyResult(parsed_2.fingerprint, passed=False, reason="HTTPS_FAILED")

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                ru_verify_main(["--root", str(root), "--core", str(core)])

            stats = json.loads((root / "stats.json").read_text())
            self.assertTrue(stats.get("incomplete"))
            self.assertEqual(stats.get("incomplete_reason"), "EXHAUSTIVE_VALIDATION_INCOMPLETE")

    # 20. LKG protection still works on infrastructure failure
    def test_20_lkg_protection_on_infra_failure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir(parents=True)
            (root / "data").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            configs = [
                _make_config(str(i), lane="main", host=f"140.82.112.{i + 1}") for i in range(12)
            ]
            from swiftproxy.parsing import serialize_uri

            (root / "sub/main.txt").write_text("\n".join(serialize_uri(c) for c in configs) + "\n")
            (root / "data/order.json").write_text(json.dumps({"main": []}))
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "production": {"main": 0, "white": 0},
                    }
                )
            )

            async def fake_verify_single(cfg, *args, **kwargs):
                return RuVerifyResult(
                    cfg.fingerprint,
                    passed=False,
                    reason="INFRA_FAIL",
                    is_infrastructure_failure=True,
                )

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                exit_code = ru_verify_main(["--root", str(root), "--core", str(core)])

            self.assertEqual(exit_code, 1)

    @patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"})
    @patch(
        "swiftproxy.ru_verify._mac_preflight",
        new=AsyncMock(return_value=MacPreflightResult(True, "wlan0", True, 3, 3, True)),
    )
    def test_cloud_handoff_is_distinct_from_final_publication(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub/happ").mkdir(parents=True)
            (root / "data/mac-candidates").mkdir(parents=True)
            core = root / "sing-box"
            core.write_text("")
            from swiftproxy.parsing import parse_uri, serialize_uri

            old_cfg = _make_config("old", lane="main")
            candidate = _make_config("prepared", lane="main", host="1.0.0.1")
            parsed_candidate = parse_uri(serialize_uri(candidate))
            (root / "sub/main.txt").write_text(serialize_uri(old_cfg) + "\n")
            (root / "sub/white.txt").write_text("")
            (root / "sub/happ/main.txt").write_text("#profile-title: Swift Main\n")
            (root / "sub/happ/white.txt").write_text("#profile-title: Swift White\n")
            (root / "data/mac-candidates/main.txt").write_text(serialize_uri(candidate) + "\n")
            (root / "data/mac-candidates/white.txt").write_text("")
            (root / "data/order.json").write_text(json.dumps({"main": [], "white": []}))
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "published": False,
                        "stage": "cloud_prepared",
                        "production": {"main": 1, "white": 0},
                    }
                )
            )

            tested = []

            async def fake_verify_single(cfg, *args, **kwargs):
                tested.append(cfg.fingerprint)
                return RuVerifyResult(
                    cfg.fingerprint,
                    passed=True,
                    r1_kbps=100.0,
                    r2_kbps=100.0,
                    https_passed=3,
                )

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify_single):
                from swiftproxy.ru_verify import main as ru_verify_main

                exit_code = ru_verify_main(["--root", str(root), "--core", str(core)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(tested, [parsed_candidate.fingerprint])
            published = parse_uri((root / "sub/main.txt").read_text().strip())
            self.assertEqual(published.fingerprint, parsed_candidate.fingerprint)
            self.assertFalse((root / "data/mac-candidates").exists())
            stats = json.loads((root / "stats.json").read_text())
            self.assertTrue(stats["published"])
            self.assertEqual(stats["stage"], "production")

    @patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"})
    @patch(
        "swiftproxy.ru_verify._mac_preflight",
        new=AsyncMock(return_value=MacPreflightResult(True, "wlan0", True, 3, 3, True)),
    )
    def test_exhaustive_counters_use_resolved_cloud_population(self):
        configs = [_make_config(str(index), host=f"11.{index}.0.1") for index in range(100)]
        resolved = {config.fingerprint for config in configs[:90]}
        results = {}
        for index, config in enumerate(configs[:90]):
            result = TestResult(
                config.fingerprint,
                "main",
                "2026-08-31T00:00:00Z",
                success_count=1 if index < 40 else 0,
                reason=None if index < 40 else "PROXY_FAILED",
            )
            results[(config.fingerprint, "main")] = result

        counts = _cloud_lane_counts("main", configs, resolved, results, 20, 20)
        self.assertEqual(
            counts,
            {
                "main_resolution_failed": 10,
                "main_cloud_expected": 90,
                "main_cloud_tested": 90,
                "main_cloud_untested": 0,
                "main_cloud_worked": 40,
                "main_cloud_pass": 40,
                "main_history_eligible": 20,
                "main_mac_expected": 20,
                "main_cloud_completion_pct": 100.0,
            },
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub/happ").mkdir(parents=True)
            (root / "data/mac-candidates").mkdir(parents=True)
            candidates = configs[:20]
            (root / "data/mac-candidates/main.txt").write_text(
                "\n".join(serialize_uri(config) for config in candidates) + "\n"
            )
            (root / "data/mac-candidates/white.txt").write_text("")
            funnel_main = {
                "main_unique": 100,
                **counts,
                "main_mac_tested": 0,
                "main_mac_untested": 20,
                "main_mac_sustained_pass": 0,
                "main_published": 0,
            }
            (root / "stats.json").write_text(
                json.dumps(
                    {
                        "project": "Swift",
                        "tagline": "Filter the garbage. Keep what works.",
                        "funnel": {"main": funnel_main},
                    }
                )
            )

            passing = {parse_uri(serialize_uri(config)).fingerprint for config in candidates[:5]}

            async def fake_verify(config, *args):
                return RuVerifyResult(
                    config.fingerprint,
                    passed=config.fingerprint in passing,
                    reason=None if config.fingerprint in passing else "HTTPS_FAILED",
                    r1_kbps=100.0 if config.fingerprint in passing else 0.0,
                    r2_kbps=100.0 if config.fingerprint in passing else 0.0,
                    https_passed=3 if config.fingerprint in passing else 0,
                )

            with patch("swiftproxy.ru_verify._verify_single", side_effect=fake_verify):
                self.assertEqual(asyncio.run(run_ru_verify(root, "sing-box")), 0)

            funnel = json.loads((root / "stats.json").read_text())["funnel"]["main"]
            expected = {
                "main_unique": 100,
                "main_resolution_failed": 10,
                "main_cloud_expected": 90,
                "main_cloud_tested": 90,
                "main_cloud_untested": 0,
                "main_cloud_pass": 40,
                "main_history_eligible": 20,
                "main_mac_expected": 20,
                "main_mac_tested": 20,
                "main_mac_untested": 0,
                "main_mac_sustained_pass": 5,
                "main_published": 5,
            }
            for key, value in expected.items():
                self.assertEqual(funnel[key], value, key)

    @patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"})
    @patch(
        "swiftproxy.ru_verify._mac_preflight",
        new=AsyncMock(return_value=MacPreflightResult(True, "wlan0", True, 3, 3, True)),
    )
    def test_mac_crash_preserves_production_and_handoff(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub/happ").mkdir(parents=True)
            (root / "data/mac-candidates").mkdir(parents=True)
            old = _make_config("old", host="12.1.0.1")
            candidate = _make_config("candidate", host="12.2.0.1")
            originals = {
                root / "sub/main.txt": serialize_uri(old) + "\n",
                root / "sub/white.txt": "",
                root / "sub/happ/main.txt": "#profile-title: Swift Main\nold\n",
                root / "sub/happ/white.txt": "#profile-title: Swift White\n",
            }
            for path, content in originals.items():
                path.write_text(content)
            (root / "data/mac-candidates/main.txt").write_text(serialize_uri(candidate) + "\n")
            (root / "data/mac-candidates/white.txt").write_text("")

            async def crash(*args):
                raise RuntimeError("simulated Mac interruption")

            with patch("swiftproxy.ru_verify._verify_single", side_effect=crash):
                with self.assertRaisesRegex(RuntimeError, "simulated Mac interruption"):
                    asyncio.run(run_ru_verify(root, "sing-box"))

            for path, content in originals.items():
                self.assertEqual(path.read_text(), content)
            self.assertTrue((root / "data/mac-candidates/main.txt").exists())

    @patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"})
    @patch(
        "swiftproxy.ru_verify._mac_preflight",
        new=AsyncMock(
            return_value=MacPreflightResult(False, "wlan0", False, 1, 3, False, {"DNS_FAILED": 1})
        ),
    )
    def test_failed_mac_preflight_preserves_production_and_handoff(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir()
            (root / "data/mac-candidates").mkdir(parents=True)
            old = serialize_uri(_make_config("old-preflight", host="12.3.0.1")) + "\n"
            candidate = serialize_uri(_make_config("candidate-preflight", host="12.4.0.1")) + "\n"
            (root / "sub/main.txt").write_text(old)
            (root / "sub/white.txt").write_text("")
            (root / "data/mac-candidates/main.txt").write_text(candidate)
            (root / "data/mac-candidates/white.txt").write_text("")

            self.assertEqual(asyncio.run(run_ru_verify(root, "sing-box")), 1)
            self.assertEqual((root / "sub/main.txt").read_text(), old)
            self.assertEqual((root / "data/mac-candidates/main.txt").read_text(), candidate)

    def test_unhealthy_collapse_postflight_preserves_last_known_good(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir()
            (root / "data/mac-candidates").mkdir(parents=True)
            old = serialize_uri(_make_config("old-collapse", host="12.5.0.1")) + "\n"
            candidate = serialize_uri(_make_config("candidate-collapse", host="12.6.0.1")) + "\n"
            (root / "sub/main.txt").write_text(old)
            (root / "sub/white.txt").write_text("")
            (root / "data/mac-candidates/main.txt").write_text(candidate)
            (root / "data/mac-candidates/white.txt").write_text("")
            healthy = MacPreflightResult(True, "wlan0", True, 3, 3, True)
            unhealthy = MacPreflightResult(False, "wlan0", True, 0, 3, False, {"CURL_28": 4})

            async def proxy_failure(config, *args):
                return RuVerifyResult(config.fingerprint, False, reason="HTTPS_FAILED")

            with (
                patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"}),
                patch(
                    "swiftproxy.ru_verify._mac_preflight",
                    new=AsyncMock(side_effect=[healthy, unhealthy]),
                ),
                patch("swiftproxy.ru_verify._verify_single", side_effect=proxy_failure),
            ):
                self.assertEqual(asyncio.run(run_ru_verify(root, "sing-box")), 1)

            self.assertEqual((root / "sub/main.txt").read_text(), old)
            self.assertEqual((root / "data/mac-candidates/main.txt").read_text(), candidate)

    def test_healthy_postflight_allows_genuine_zero_proxy_result(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub").mkdir()
            (root / "data/mac-candidates").mkdir(parents=True)
            old = serialize_uri(_make_config("old-zero", host="12.7.0.1")) + "\n"
            candidate = serialize_uri(_make_config("candidate-zero", host="12.8.0.1")) + "\n"
            (root / "sub/main.txt").write_text(old)
            (root / "sub/white.txt").write_text("")
            (root / "data/mac-candidates/main.txt").write_text(candidate)
            (root / "data/mac-candidates/white.txt").write_text("")
            healthy = MacPreflightResult(True, "wlan0", True, 3, 3, True)

            async def proxy_failure(config, *args):
                return RuVerifyResult(config.fingerprint, False, reason="HTTPS_FAILED")

            with (
                patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"}),
                patch(
                    "swiftproxy.ru_verify._mac_preflight",
                    new=AsyncMock(side_effect=[healthy, healthy]),
                ),
                patch("swiftproxy.ru_verify._verify_single", side_effect=proxy_failure),
            ):
                self.assertEqual(asyncio.run(run_ru_verify(root, "sing-box")), 0)

            self.assertEqual((root / "sub/main.txt").read_text(), "")
            self.assertFalse((root / "data/mac-candidates").exists())

    def test_final_subscription_batch_rolls_back_on_write_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub/happ").mkdir(parents=True)
            old = _make_config("old", host="13.1.0.1")
            new = _make_config("new", host="13.2.0.1")
            originals = {
                root / "sub/main.txt": serialize_uri(old) + "\n",
                root / "sub/white.txt": "",
                root / "sub/happ/main.txt": "#profile-title: Swift Main\nold\n",
                root / "sub/happ/white.txt": "#profile-title: Swift White\n",
            }
            for path, content in originals.items():
                path.write_text(content)

            from swiftproxy.output import atomic_write

            calls = 0

            def fail_once(path, content):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated replace failure")
                return atomic_write(path, content)

            with patch("swiftproxy.output.atomic_write", side_effect=fail_once):
                with self.assertRaisesRegex(OSError, "simulated replace failure"):
                    write_final_subscriptions(
                        root,
                        [serialize_uri(new)],
                        [],
                        "https://github.com/femboypig/Swift",
                    )

            for path, content in originals.items():
                self.assertEqual(path.read_text(), content)

    @patch.dict("os.environ", {"SWIFT_BIND_INTERFACE": "wlan0"})
    @patch(
        "swiftproxy.ru_verify._mac_preflight",
        new=AsyncMock(return_value=MacPreflightResult(True, "wlan0", True, 3, 3, True)),
    )
    def test_mac_publication_failure_keeps_handoff_and_production(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "sub/happ").mkdir(parents=True)
            (root / "data/mac-candidates").mkdir(parents=True)
            old = _make_config("old-publication", host="14.1.0.1")
            candidate = _make_config("new-publication", host="14.2.0.1")
            old_main = serialize_uri(old) + "\n"
            (root / "sub/main.txt").write_text(old_main)
            (root / "sub/white.txt").write_text("")
            (root / "data/mac-candidates/main.txt").write_text(serialize_uri(candidate) + "\n")
            (root / "data/mac-candidates/white.txt").write_text("")

            async def pass_candidate(config, *args):
                return RuVerifyResult(
                    config.fingerprint,
                    passed=True,
                    r1_kbps=100.0,
                    r2_kbps=100.0,
                    https_passed=3,
                )

            with (
                patch("swiftproxy.ru_verify._verify_single", side_effect=pass_candidate),
                patch(
                    "swiftproxy.ru_verify.write_final_subscriptions",
                    side_effect=OSError("simulated publication failure"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "simulated publication failure"):
                    asyncio.run(run_ru_verify(root, "sing-box"))

            self.assertEqual((root / "sub/main.txt").read_text(), old_main)
            self.assertTrue((root / "data/mac-candidates/main.txt").exists())

    def test_tcp_tls_telemetry_reports_sample_scope(self):
        targets = [
            {"host": "1.1.1.1", "port": 443, "sni": "one.example"},
            {"host": "8.8.8.8", "port": 443, "sni": "two.example"},
            {"host": "9.9.9.9", "port": 443, "sni": "three.example"},
        ]
        telemetry = _tcp_tls_telemetry_counts(
            targets,
            {
                "1.1.1.1:443": {"ok": True},
                "8.8.8.8:443": {"ok": False},
            },
            eligible_population=1435,
        )
        self.assertEqual(telemetry["tcp_tls_telemetry_population"], 1435)
        self.assertEqual(telemetry["tcp_tls_telemetry_expected"], 3)
        self.assertEqual(telemetry["tcp_tls_telemetry_tested"], 2)
        self.assertEqual(telemetry["white_tcp_tls_pass"], 1)
        self.assertEqual(telemetry["white_tcp_tls_fail"], 1)
        self.assertEqual(telemetry["white_tcp_tls_unknown"], 1)
        self.assertIn("max 60", telemetry["tcp_tls_telemetry_sampling_policy"])


if __name__ == "__main__":
    unittest.main()
