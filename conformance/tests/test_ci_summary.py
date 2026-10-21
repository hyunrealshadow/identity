import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_summary import generate_summary
from plans import ci_cases


class SummaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = {
            "PROFILES": json.dumps(["basic"]),
            "GITHUB_SERVER_URL": "https://github.example",
            "GITHUB_REPOSITORY": "owner/identity",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SHA": "abc123",
            "GITHUB_REF_NAME": "main",
            "PREPARE_RESULT": "success",
            "PLAN_JOBS_RESULT": "success",
        }

    def report(self, case_id="basic", outcomes=("PASSED",), statuses=None, expected=None, **overrides):
        directory = self.root / f"oidc-conformance-{case_id}-123-2"
        directory.mkdir(exist_ok=True)
        counts = {key: outcomes.count(key) for key in (
            "PASSED", "FAILED", "WARNING", "SKIPPED", "REVIEW", "MANUAL_REVIEW_REQUIRED"
        )}
        statuses = statuses or ["FINISHED"] * len(outcomes)
        report = {
            "case_id": case_id,
            "profile": "basic",
            "response_type": None,
            "summary": counts,
            "results": [{"status": status, "result": result} for status, result in zip(statuses, outcomes)],
            "plan": {"modules": [None] * (expected if expected is not None else len(outcomes))},
            "plan_url": "https://suite.example/plan-detail.html?plan=one&public=true",
        }
        report.update(overrides)
        (directory / "results.json").write_text(json.dumps(report), encoding="utf-8")
        return directory

    def summary(self):
        return generate_summary(self.root, self.environment)

    def test_complete_report_links_exact_run_attempt_and_commit(self):
        self.report(outcomes=("PASSED", "WARNING", "SKIPPED", "REVIEW"))
        summary = self.summary()
        self.assertIn("https://github.example/owner/identity/actions/runs/123/attempts/2", summary)
        self.assertIn("https://github.example/owner/identity/commit/abc123", summary)
        self.assertIn("<!-- oidc-conformance: run_id=123 run_attempt=2 -->", summary)
        self.assertIn("| basic | — | COMPLETED | 1 | 0 | 1 | 1 | 1 |", summary)
        self.assertIn("does not establish OpenID certification", summary)

    def test_failed_and_incomplete_reports_cannot_become_completed(self):
        for outcomes, statuses, expected, status in [
            (("FAILED",), None, None, "FAILED"),
            (("PASSED",), None, 2, "INCOMPLETE"),
            (("PASSED",), ["RUNNING"], None, "INCOMPLETE"),
            (("MANUAL_REVIEW_REQUIRED",), ["MANUAL_REVIEW_REQUIRED"], None, "INCOMPLETE"),
            ((), None, 0, "INCOMPLETE"),
        ]:
            with self.subTest(outcomes=outcomes, statuses=statuses, expected=expected):
                self.report(outcomes=outcomes, statuses=statuses, expected=expected)
                self.assertIn(f"| basic | — | {status} |", self.summary())

    def test_missing_report_keeps_official_plan_link(self):
        directory = self.root / "oidc-conformance-basic-123"
        directory.mkdir()
        (directory / "plan-url.txt").write_text("https://suite.example/plan-detail.html?plan=partial\n")
        summary = self.summary()
        self.assertIn("| basic | — | NO_REPORT | — | — | — | — | — |", summary)
        self.assertIn("[Plan](https://suite.example/plan-detail.html?plan=partial)", summary)

    def test_corrupt_report_is_incomplete_and_does_not_hide_other_cases(self):
        self.environment["PROFILES"] = json.dumps(["basic", "hybrid"])
        directory = self.report()
        (directory / "results.json").write_text("{invalid", encoding="utf-8")
        (directory / "plan-url.txt").write_text("https://suite.example/plan-detail.html?plan=broken")
        summary = self.summary()
        self.assertIn("| basic | — | INCOMPLETE |", summary)
        self.assertIn("| hybrid | — | NO_REPORT |", summary)
        self.assertIn("plan=broken", summary)

    def test_response_type_cases_do_not_overwrite_each_other(self):
        self.environment["PROFILES"] = json.dumps(["dynamic-code", "dynamic-id-token"])
        self.report("dynamic-code", profile="dynamic", response_type="code")
        self.report("dynamic-id-token", outcomes=("FAILED",), profile="dynamic", response_type="id_token")
        summary = self.summary()
        self.assertIn("| dynamic-code | code | COMPLETED |", summary)
        self.assertIn("| dynamic-id-token | id_token | FAILED |", summary)

    def test_rerun_uses_numeric_latest_attempt_even_when_report_is_missing(self):
        directory = self.report()
        directory.rename(directory.with_name("oidc-conformance-basic-123-9"))
        latest = self.root / "oidc-conformance-basic-123-10"
        latest.mkdir()
        (latest / "plan-url.txt").write_text("https://suite.example/plan-detail.html?plan=attempt10")
        self.environment["GITHUB_RUN_ATTEMPT"] = "10"
        summary = self.summary()
        self.assertIn("| basic | — | NO_REPORT |", summary)
        self.assertNotIn("| COMPLETED |", summary)
        self.assertIn("plan=attempt10", summary)

    def test_rerun_reuses_previous_success_but_corrupt_latest_report_replaces_it(self):
        self.environment["PROFILES"] = json.dumps(["basic", "hybrid"])
        self.report()
        directory = self.report("hybrid")
        latest = directory.with_name("oidc-conformance-hybrid-123-3")
        latest.mkdir()
        (latest / "results.json").write_text("{broken", encoding="utf-8")
        self.environment["GITHUB_RUN_ATTEMPT"] = "3"
        summary = self.summary()
        self.assertIn("| basic | — | COMPLETED |", summary)
        self.assertIn("| hybrid | — | INCOMPLETE |", summary)

    def test_prepare_failure_lists_every_expected_case(self):
        self.environment.pop("PROFILES")
        self.environment["PREPARE_RESULT"] = "failure"
        self.environment["PLAN_JOBS_RESULT"] = "skipped"
        summary = self.summary()
        self.assertEqual(summary.count("| NO_REPORT |"), len(ci_cases()))
        self.assertIn("Preparation: **failure**", summary)
        self.assertIn("Plan jobs: **skipped**", summary)
        self.assertIn("| dynamic-id-token-token | id_token token | NO_REPORT |", summary)

    def test_invalid_counts_and_unsafe_links_are_not_reported_as_success(self):
        self.report(summary={"PASSED": -1}, plan_url="javascript:alert(1)")
        summary = self.summary()
        self.assertIn("| basic | — | INCOMPLETE | 1 | 0 |", summary)
        self.assertNotIn("javascript:", summary)

    def test_contradictory_summary_preserves_actual_failure_and_is_incomplete(self):
        self.report(outcomes=("FAILED",), summary={"PASSED": 1})
        summary = self.summary()
        self.assertIn("| basic | — | INCOMPLETE | 0 | 1 |", summary)
        self.assertNotIn("| COMPLETED |", summary)
        self.assertIn("**0** passed, **1** failed", summary)

    def test_cli_writes_standalone_and_step_summary(self):
        self.report()
        output = self.root / "output" / "SUMMARY.md"
        step_summary = self.root / "step.md"
        step_summary.write_text("Earlier step\n", encoding="utf-8")
        environment = {**os.environ, **self.environment, "GITHUB_STEP_SUMMARY": str(step_summary)}
        script = Path(__file__).resolve().parents[1] / "ci_summary.py"
        subprocess.run(
            [sys.executable, str(script), "--reports-dir", str(self.root), "--output", str(output)],
            env=environment, check=True, capture_output=True, text=True,
        )
        standalone = output.read_text(encoding="utf-8")
        self.assertTrue(standalone.startswith("# OIDC conformance summary\n"))
        self.assertEqual(step_summary.read_text(encoding="utf-8"), "Earlier step\n" + standalone)


if __name__ == "__main__":
    unittest.main()
