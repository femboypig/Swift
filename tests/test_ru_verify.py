from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swiftproxy.ru_verify import run_ru_verify


class TestRuVerify(unittest.TestCase):
    def test_ru_verify_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            res = unittest.mock.AsyncMock()
            # empty folder
            import asyncio
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

            from swiftproxy.parsing import parse_uri
            cfg1 = parse_uri(line1)
            cfg2 = parse_uri(line2)

            async def fake_verify(config, *args):
                if config.fingerprint == cfg1.fingerprint:
                    return config.fingerprint, True, None
                return config.fingerprint, False, "BLOCKED"

            mock_verify.side_effect = fake_verify

            import asyncio
            code = asyncio.run(run_ru_verify(root, "sing-box"))
            self.assertEqual(code, 0)

            remaining = main_file.read_text().splitlines()
            self.assertEqual(len(remaining), 1)
            self.assertIn("node1", remaining[0])


if __name__ == "__main__":
    unittest.main()
