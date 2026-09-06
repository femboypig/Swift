import io
import json
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from swiftproxy.ru_probe import probe_ru_targets


class TestRuProbe(unittest.TestCase):
    def test_probe_no_url(self):
        res = probe_ru_targets([{"host": "1.1.1.1", "port": 443}], probe_url="")
        self.assertEqual(res, {})

    @patch.dict("os.environ", {}, clear=True)
    def test_probe_no_env(self):
        res = probe_ru_targets([{"host": "1.1.1.1", "port": 443}])
        self.assertEqual(res, {})

    def test_probe_no_targets(self):
        res = probe_ru_targets([], probe_url="https://example.com/probe")
        self.assertEqual(res, {})

    @patch("urllib.request.urlopen")
    def test_probe_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_data = {
            "control": {"telegram_ok": True},
            "results": [
                {
                    "target": {"id": "proxy-a", "host": "1.2.3.4", "port": 443},
                    "ok": True,
                    "latency_ms": 42,
                    "error": None,
                },
                {
                    "target": {"id": "proxy-b", "host": "5.6.7.8", "port": 8443},
                    "ok": False,
                    "latency_ms": None,
                    "error": "ConnectionRefusedError",
                },
            ]
        }
        mock_response.read.return_value = json.dumps(mock_data).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        targets = [
            {"id": "proxy-a", "host": "1.2.3.4", "port": 443},
            {"id": "proxy-b", "host": "5.6.7.8", "port": 8443},
        ]
        res = probe_ru_targets(
            targets, probe_url="https://example.com/probe", probe_key="secret123"
        )
        self.assertEqual(len(res), 2)
        self.assertTrue(res["proxy-a"]["ok"])
        self.assertEqual(res["proxy-a"]["latency_ms"], 42)
        self.assertFalse(res["proxy-b"]["ok"])

    @patch("urllib.request.urlopen")
    def test_probe_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://example.com", code=500, msg="Server Error", hdrs={}, fp=io.BytesIO()
        )
        res = probe_ru_targets(
            [{"id": "proxy-a", "host": "1.2.3.4", "port": 443}],
            probe_url="https://example.com/probe",
        )
        self.assertEqual(res, {})

    @patch("urllib.request.urlopen")
    def test_probe_chunking(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            {
                "control": {"telegram_ok": True},
                "results": [
                    {
                        "target": {"id": "proxy-a", "host": "1.2.3.4", "port": 443},
                        "ok": True,
                        "latency_ms": 42,
                    }
                ],
            }
        ).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        targets = [{"id": f"proxy-{index}", "host": "1.2.3.4", "port": 443} for index in range(3)]
        res = probe_ru_targets(targets, probe_url="https://example.com/probe", chunk_size=1)
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(res, {})

    def test_probe_rejects_missing_or_duplicate_identifiers(self):
        for targets in (
            [{"host": "1.2.3.4", "port": 443}],
            [{"id": "same", "host": "1.2.3.4", "port": 443}] * 2,
        ):
            with self.subTest(targets=targets):
                self.assertEqual(probe_ru_targets(targets, probe_url="https://example.com/probe"), {})


if __name__ == "__main__":
    unittest.main()
