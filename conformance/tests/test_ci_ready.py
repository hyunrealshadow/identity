import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ci_ready import wait_until_ready


def response(payload):
    result = MagicMock()
    result.json.return_value = payload
    return result


class ReadinessTests(unittest.TestCase):
    @patch("ci_ready.ConformanceClient")
    @patch("ci_ready.requests.get")
    def test_root_issuer_matches_url_serialization_and_checks_login_and_suite(self, get, client):
        discovery = response({"issuer": "https://op.example/"})
        login = response({"status": "ready"})
        get.side_effect = [
            discovery,
            login,
        ]
        client.return_value.session.get.side_effect = [response([]), response({})]

        wait_until_ready("https://op.example", "https://suite.example/", login_url="https://login.example/")

        self.assertEqual(get.call_args_list[0].args[0], "https://op.example/.well-known/openid-configuration")
        self.assertEqual(get.call_args_list[1].args[0], "https://login.example/health/ready")
        self.assertEqual(client.return_value.session.get.call_count, 2)
        discovery.raise_for_status.assert_called_once()
        login.raise_for_status.assert_called_once()

    @patch("ci_ready.time.sleep")
    @patch("ci_ready.time.monotonic", side_effect=[0, 0, 181])
    @patch("ci_ready.ConformanceClient")
    @patch("ci_ready.requests.get")
    def test_rejects_different_issuer_and_reports_both_values(self, get, client, _clock, _sleep):
        for issuer in ("https://other.example/", "http://op.example/", "https://op.example/unexpected"):
            with self.subTest(issuer=issuer):
                _clock.side_effect = [0, 0, 181]
                get.return_value = response({"issuer": issuer})
                with self.assertRaisesRegex(RuntimeError, "expected 'https://op.example/', got"):
                    wait_until_ready("https://op.example", "https://suite.example")
        client.return_value.session.get.assert_not_called()

    @patch("ci_ready.ConformanceClient")
    @patch("ci_ready.requests.get")
    def test_preserves_path_issuer_and_explicit_root_slash(self, get, client):
        for issuer in ("https://op.example/", "https://op.example/tenant"):
            with self.subTest(issuer=issuer):
                get.return_value = response({"issuer": issuer})
                client.return_value.session.get.side_effect = [response([]), response({})]
                wait_until_ready(issuer, "https://suite.example")

    @patch("ci_ready.time.sleep")
    @patch("ci_ready.time.monotonic", side_effect=[0, 0, 181])
    @patch("ci_ready.ConformanceClient")
    @patch("ci_ready.requests.get")
    def test_unready_login_does_not_start_suite_checks(self, get, client, _clock, _sleep):
        get.side_effect = [response({"issuer": "https://op.example/"}), response({"status": "unready"})]
        with self.assertRaisesRegex(RuntimeError, "Login application is not ready"):
            wait_until_ready("https://op.example", "https://suite.example", login_url="https://login.example")
        client.return_value.session.get.assert_not_called()
