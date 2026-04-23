import os
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.client import TestInfo, TestModule
from scripts.runner import TestRunner


class FakeClient:
    def __init__(self, modules, info_sequences, browser_urls=None, start_run_ids=None):
        self.modules = modules
        self.info_sequences = {run_id: list(sequence) for run_id, sequence in info_sequences.items()}
        self.browser_urls = browser_urls or {}
        self.start_run_ids = start_run_ids or {}
        self.started_tests = []

    def get_modules(self, _plan_id):
        return self.modules

    def select_preferred_instance(self, instances):
        if not instances:
            return None

        active_statuses = {"CREATED", "CONFIGURED", "RUNNING", "WAITING"}
        for instance_id in reversed(instances):
            info = self.info_sequences[instance_id][0]
            if info.status in active_statuses:
                return instance_id
        return instances[-1]

    def get_test_info(self, run_id):
        sequence = self.info_sequences[run_id]
        if len(sequence) > 1:
            return sequence.pop(0)
        return sequence[0]

    def get_test_status(self, run_id):
        urls = self.browser_urls.get(run_id, [])
        if not urls:
            return {"browser": {"urlsWithMethod": []}}

        return {
            "browser": {
                "urlsWithMethod": [{"url": urls[0], "method": "GET"}],
            }
        }

    def get_browser_urls(self, run_id):
        return self.browser_urls.get(run_id, [])

    def get_pending_screenshots(self, _run_id):
        return []

    def upload_screenshot(self, _run_id, _upload_id, _image_data):
        return False

    def start_test(self, plan_id, test_name, variant):
        run_id = self.start_run_ids[test_name]
        self.started_tests.append((plan_id, test_name, variant, run_id))
        return run_id


class FakeAutoLogin:
    def __init__(self):
        self.reset_calls = 0
        self.handled_urls = []

    def reset_session(self):
        self.reset_calls += 1

    def handle_auth_url(self, auth_url, method="GET"):
        self.handled_urls.append((auth_url, method))
        return True

    def create_placeholder_screenshot(self):
        return "placeholder"


class TestRunnerResumeTests(unittest.TestCase):
    @patch("scripts.runner.time.sleep", return_value=None)
    def test_run_single_test_resumes_waiting_instance(self, _sleep):
        run_id = "waiting-run"
        client = FakeClient(
            modules=[TestModule("oidcc-claims-locales", {}, [run_id], "")],
            info_sequences={
                run_id: [
                    TestInfo(run_id, "WAITING", None),
                    TestInfo(run_id, "WAITING", None),
                    TestInfo(run_id, "FINISHED", "PASSED"),
                ]
            },
            browser_urls={run_id: ["http://identity:5150/oauth2/authorize?claims_locales=se"]},
        )
        auto_login = FakeAutoLogin()
        runner = TestRunner(client, auto_login, timeout_per_test=5, poll_interval=1)

        result = runner.run_single_test("plan-1", "oidcc-claims-locales", {})

        self.assertEqual(result.status, "FINISHED")
        self.assertEqual(result.result, "PASSED")
        self.assertEqual(result.run_id, run_id)
        self.assertEqual(client.started_tests, [])
        self.assertEqual(auto_login.reset_calls, 1)
        self.assertEqual(
            auto_login.handled_urls,
            [("http://identity:5150/oauth2/authorize?claims_locales=se", "GET")],
        )

    @patch("scripts.runner.time.sleep", return_value=None)
    def test_run_all_tests_resumes_active_instance_before_starting_next_test(self, _sleep):
        waiting_run_id = "waiting-run"
        fresh_run_id = "fresh-run"
        client = FakeClient(
            modules=[
                TestModule("oidcc-claims-locales", {}, [waiting_run_id], ""),
                TestModule("oidcc-next", {"variant": "fresh"}, [], ""),
            ],
            info_sequences={
                waiting_run_id: [
                    TestInfo(waiting_run_id, "WAITING", None),
                    TestInfo(waiting_run_id, "WAITING", None),
                    TestInfo(waiting_run_id, "WAITING", None),
                    TestInfo(waiting_run_id, "FINISHED", "PASSED"),
                ],
                fresh_run_id: [
                    TestInfo(fresh_run_id, "WAITING", None),
                    TestInfo(fresh_run_id, "FINISHED", "PASSED"),
                ],
            },
            browser_urls={
                waiting_run_id: ["http://identity:5150/oauth2/authorize?claims_locales=se"],
                fresh_run_id: ["http://identity:5150/oauth2/authorize?client_id=fresh"],
            },
            start_run_ids={"oidcc-next": fresh_run_id},
        )
        auto_login = FakeAutoLogin()
        runner = TestRunner(client, auto_login, timeout_per_test=5, poll_interval=1)

        results = runner.run_all_tests("plan-1")

        self.assertEqual([result.status for result in results], ["FINISHED", "FINISHED"])
        self.assertEqual([result.result for result in results], ["PASSED", "PASSED"])
        self.assertEqual([result.run_id for result in results], [waiting_run_id, fresh_run_id])
        self.assertEqual(client.started_tests, [("plan-1", "oidcc-next", {"variant": "fresh"}, fresh_run_id)])
        self.assertEqual(auto_login.reset_calls, 2)
        self.assertEqual(
            auto_login.handled_urls,
            [
                ("http://identity:5150/oauth2/authorize?claims_locales=se", "GET"),
                ("http://identity:5150/oauth2/authorize?client_id=fresh", "GET"),
            ],
        )

    @patch("scripts.runner.time.sleep", return_value=None)
    def test_run_single_test_prefers_latest_active_instance(self, _sleep):
        interrupted_run_id = "interrupted-run"
        waiting_run_id = "waiting-run"
        client = FakeClient(
            modules=[
                TestModule("oidcc-claims-locales", {}, [interrupted_run_id, waiting_run_id], "")
            ],
            info_sequences={
                interrupted_run_id: [TestInfo(interrupted_run_id, "INTERRUPTED", None)],
                waiting_run_id: [
                    TestInfo(waiting_run_id, "WAITING", None),
                    TestInfo(waiting_run_id, "WAITING", None),
                    TestInfo(waiting_run_id, "FINISHED", "PASSED"),
                ],
            },
            browser_urls={waiting_run_id: ["http://identity:5150/oauth2/authorize?claims_locales=se"]},
        )
        auto_login = FakeAutoLogin()
        runner = TestRunner(client, auto_login, timeout_per_test=5, poll_interval=1)

        result = runner.run_single_test("plan-1", "oidcc-claims-locales", {})

        self.assertEqual(result.status, "FINISHED")
        self.assertEqual(result.result, "PASSED")
        self.assertEqual(result.run_id, waiting_run_id)
        self.assertEqual(client.started_tests, [])
        self.assertEqual(
            auto_login.handled_urls,
            [("http://identity:5150/oauth2/authorize?claims_locales=se", "GET")],
        )


if __name__ == "__main__":
    unittest.main()
