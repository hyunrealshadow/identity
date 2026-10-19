import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_publish import publish_results


class PublishResultsTests(unittest.TestCase):
    def test_cli_accepts_container_results_directory(self):
        script = Path(__file__).resolve().parents[1] / "ci_publish.py"
        result = subprocess.run(
            [sys.executable, str(script), "--results-dir", str(self.results / "missing")],
            capture_output=True, text=True, check=True,
        )
        self.assertIn("No plan was created", result.stdout)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.results = Path(temporary.name)
        self.plan_file = self.results / "plan-url.txt"
        self.plan_file.write_text("https://suite.example/plan-detail.html?plan=failed-plan\n")
        environment = patch.dict(os.environ, {
            "SUITE_URL": "https://suite.example",
            "CONFORMANCE_API_TOKEN": "test-token",
        })
        environment.start()
        self.addCleanup(environment.stop)

    @patch("ci_publish.urlopen")
    def test_publishes_failed_plan_and_updates_report_link(self, open_url):
        report_file = self.results / "results.json"
        report_file.write_text(json.dumps({"summary": {"FAILED": 1}, "plan_url": "old"}))
        publish_results(self.results)
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://suite.example/api/plan/failed-plan/publish")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertEqual(json.loads(request.data), {"publish": "everything"})
        report = json.loads(report_file.read_text())
        self.assertEqual(report["summary"], {"FAILED": 1})
        self.assertEqual(report["plan_url"], self.plan_file.read_text().strip())
        self.assertTrue(report["plan_url"].endswith("&public=true"))

    @patch("ci_publish.urlopen")
    def test_publishes_interrupted_plan_without_report(self, open_url):
        publish_results(self.results)
        open_url.assert_called_once()
        self.assertIn("&public=true", self.plan_file.read_text())
        self.assertFalse((self.results / "results.json").exists())

    @patch("ci_publish.urlopen")
    def test_skips_when_no_plan_was_created(self, open_url):
        self.plan_file.unlink()
        publish_results(self.results)
        open_url.assert_not_called()

    @patch("ci_publish.urlopen")
    def test_publication_error_propagates_and_keeps_private_link(self, open_url):
        original = self.plan_file.read_text()
        open_url.side_effect = HTTPError("https://suite.example", 403, "Forbidden", {}, None)
        with self.assertRaises(HTTPError):
            publish_results(self.results)
        self.assertEqual(self.plan_file.read_text(), original)

    @patch("ci_publish.urlopen")
    def test_rejects_plan_from_another_suite(self, open_url):
        self.plan_file.write_text("https://other.example/plan-detail.html?plan=123")
        with self.assertRaises(ValueError):
            publish_results(self.results)
        open_url.assert_not_called()
