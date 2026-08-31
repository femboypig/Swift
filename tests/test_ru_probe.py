import io
import json
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

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
            "results": [
                {
                    "target": {"host": "1.2.3.4", "port": 443},
                    "ok": True,
                    "latency_ms": 42,
                    "error": None,
                },
                {
                    "target": {"host": "5.6.7.8", "port": 8443},
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
            {"host": "1.2.3.4", "port": 443, "sni": "test.com"},
            {"host": "5.6.7.8", "port": 8443, "sni": "test2.com"},
        ]
        res = probe_ru_targets(
            targets, probe_url="https://example.com/probe", probe_key="secret123"
        )
        self.assertEqual(len(res), 2)
        self.assertTrue(res["1.2.3.4:443"]["ok"])
        self.assertEqual(res["1.2.3.4:443"]["latency_ms"], 42)
        self.assertFalse(res["5.6.7.8:8443"]["ok"])

    @patch("urllib.request.urlopen")
    def test_probe_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://example.com", code=500, msg="Server Error", hdrs={}, fp=io.BytesIO()
        )
        res = probe_ru_targets(
            [{"host": "1.2.3.4", "port": 443}], probe_url="https://example.com/probe"
        )
        self.assertEqual(res, {})

    @patch("urllib.request.urlopen")
    def test_probe_chunking(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            {"results": [{"target": {"host": "1.2.3.4", "port": 443}, "ok": True}]}
        ).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        targets = [
            {"host": "1.2.3.4", "port": 443},
            {"host": "1.2.3.4", "port": 443},
            {"host": "1.2.3.4", "port": 443},
        ]
        res = probe_ru_targets(targets, probe_url="https://example.com/probe", chunk_size=1)
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertTrue(res["1.2.3.4:443"]["ok"])


if __name__ == "__main__":
    unittest.main()
