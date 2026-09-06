from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from swiftproxy.verification.preflight import _direct_preflight_probe


class TestRuVerify(unittest.TestCase):
    @patch("swiftproxy.network.resolve_direct", new_callable=AsyncMock, return_value=["1.1.1.1"])
    @patch("asyncio.create_subprocess_exec")
    def test_preflight_probe_is_bound_to_requested_interface(self, mock_exec, resolve):
        process = AsyncMock()
        process.returncode = 0
        process.communicate.return_value = (b"204:0", b"")
        mock_exec.return_value = process

        result = asyncio.run(_direct_preflight_probe("wlan0", "https://example.com", timeout=4.0))

        self.assertTrue(result.ok)
        command = mock_exec.await_args.args
        interface_index = command.index("--interface")
        self.assertEqual(command[interface_index + 1], "if!wlan0")
        self.assertIn("example.com:443:1.1.1.1", command)
        resolve.assert_awaited_once_with("example.com", "wlan0", 4.0)

    @patch("asyncio.create_subprocess_exec")
    def test_preflight_probe_rejects_loopback_direct_socks(self, mock_exec):
        process = AsyncMock()
        process.returncode = 0
        process.communicate.return_value = (b"204:0", b"")
        mock_exec.return_value = process

        result = asyncio.run(
            _direct_preflight_probe(
                "wlan0",
                "https://example.com",
                timeout=4.0,
                direct_socks=("127.0.0.1", 3065),
            )
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.diagnostic, "DIRECT_SOCKS_FORBIDDEN")
        mock_exec.assert_not_called()


if __name__ == "__main__":
    unittest.main()
