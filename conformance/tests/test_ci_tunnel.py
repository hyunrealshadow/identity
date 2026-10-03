import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ci_tunnel import public_url_from_logs, wait_for_tunnel_url


def startup_logs(url):
    return (
        "tunnel-1 | INF | Your quick Tunnel has been created! Visit it at: |\n"
        f"tunnel-1 | INF |  {url}  |\n"
    )


class QuickTunnelTests(unittest.TestCase):
    def test_extracts_allocated_public_https_origin(self):
        url = "https://random-test-name.trycloudflare.com"
        self.assertEqual(public_url_from_logs(startup_logs(url)), url)

    def test_does_not_accept_provisioning_api_errors(self):
        self.assertIsNone(public_url_from_logs("failed POST https://api.trycloudflare.com/tunnel"))

    def test_rejects_unexpected_origins_or_paths(self):
        for url in (
            "http://test.trycloudflare.com",
            "https://test.trycloudflare.com.evil.example",
            "https://test.trycloudflare.com/path",
            "https://test.example.com",
        ):
            with self.subTest(url=url):
                self.assertIsNone(public_url_from_logs(startup_logs(url)))

    @patch("ci_tunnel.time.sleep")
    @patch("ci_tunnel.subprocess.run")
    def test_waits_for_allocation_then_returns_url(self, run, sleep):
        url = "https://random-test-name.trycloudflare.com"
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "Requesting new quick Tunnel", ""),
            subprocess.CompletedProcess([], 0, startup_logs(url), ""),
        ]
        self.assertEqual(wait_for_tunnel_url(), url)
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(2)

    @patch("ci_tunnel.time.monotonic", side_effect=[0, 121])
    def test_timeout_fails_instead_of_using_a_placeholder_issuer(self, _clock):
        with self.assertRaisesRegex(RuntimeError, "did not allocate"):
            wait_for_tunnel_url()
