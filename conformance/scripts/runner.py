import time
import sys
from typing import Optional
from dataclasses import dataclass

from .client import ConformanceClient, TestModule
from .auto_login import AutoLoginHandler


@dataclass
class TestResult:
    test_name: str
    status: str
    result: Optional[str]
    run_id: str


SPECIAL_TIMEOUT_TESTS = {
    "oidcc-prompt-login": 120,
    "oidcc-max-age-1": 120,
    "oidcc-max-age-10000": 120,
    "oidcc-id-token-hint": 120,
    "oidcc-prompt-none-logged-in": 120,
    "oidcc-codereuse-30seconds": 90,
}


class TestRunner:
    def __init__(
        self,
        client: ConformanceClient,
        auto_login: AutoLoginHandler,
        timeout_per_test: int = 60,
        poll_interval: int = 2,
    ):
        self.client = client
        self.auto_login = auto_login
        self.timeout_per_test = timeout_per_test
        self.poll_interval = poll_interval

    @staticmethod
    def _is_active_status(status: str) -> bool:
        return status in {"CREATED", "CONFIGURED", "RUNNING", "WAITING"}

    def _upload_screenshots(self, run_id: str) -> bool:
        try:
            pending = self.client.get_pending_screenshots(run_id)
            if not pending:
                return False
            uploaded = False
            for entry in pending:
                upload_id = entry.get("upload")
                if not upload_id or entry.get("img"):
                    continue
                screenshot = self.auto_login.create_placeholder_screenshot()
                if self.client.upload_screenshot(run_id, upload_id, screenshot):
                    print(f"    Uploaded screenshot for {upload_id}")
                    uploaded = True
            return uploaded
        except Exception:
            return False

    def run_single_test(self, plan_id: str, test_name: str, variant: dict) -> TestResult:
        modules = self.client.get_modules(plan_id)
        run_id = None

        for m in modules:
            if m.test_module == test_name:
                if m.instances:
                    run_id = self.client.select_preferred_instance(m.instances)
                    info = self.client.get_test_info(run_id)
                    if not self._is_active_status(info.status):
                        return TestResult(
                            test_name=test_name,
                            status=info.status,
                            result=info.result,
                            run_id=run_id,
                        )
                break

        self.auto_login.reset_session()
        if run_id is None:
            run_id = self.client.start_test(plan_id, test_name, variant)
        processed_urls = set()

        timeout = SPECIAL_TIMEOUT_TESTS.get(test_name, self.timeout_per_test)
        elapsed = 0
        while elapsed < timeout:
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval

            info = self.client.get_test_info(run_id)

            if info.status == "FINISHED":
                return TestResult(test_name=test_name, status="FINISHED", result=info.result, run_id=run_id)

            if info.status == "INTERRUPTED":
                return TestResult(test_name=test_name, status="INTERRUPTED", result=None, run_id=run_id)

            if info.status == "WAITING":
                status_data = self.client.get_test_status(run_id)
                url_method = "GET"
                if status_data.get("browser") and status_data["browser"].get("urlsWithMethod"):
                    method_info = status_data["browser"]["urlsWithMethod"]
                    if isinstance(method_info, list):
                        for m in method_info:
                            if m.get("method"):
                                url_method = m["method"]
                                break
                    elif isinstance(method_info, dict) and method_info.get("method"):
                        url_method = method_info["method"]

                urls = self.client.get_browser_urls(run_id)
                has_new_urls = False
                for url in urls:
                    if url in processed_urls:
                        continue
                    processed_urls.add(url)
                    has_new_urls = True
                    success = self.auto_login.handle_auth_url(url, url_method)
                    print(f"    [debug] handle_auth_url returned {success} for {url[:60]}...")
                    time.sleep(self.poll_interval)

                if not has_new_urls:
                    uploaded = self._upload_screenshots(run_id)
                    if not uploaded:
                        # Still WAITING with no new URLs and no screenshots needed.
                        # Conformance suite may be re-issuing the same URL after a failed
                        # login attempt. Clear processed_urls to allow a retry.
                        if processed_urls:
                            print(f"    [debug] WAITING with no new URLs, clearing processed_urls to retry")
                            processed_urls.clear()

        return TestResult(test_name=test_name, status="TIMEOUT", result=None, run_id=run_id)

    def run_all_tests(self, plan_id: str) -> list[TestResult]:
        modules = self.client.get_modules(plan_id)
        results = []
        total = len(modules)

        for i, m in enumerate(modules):
            print(f"[{i + 1}/{total}] {m.test_module}", end="", flush=True)

            if m.instances:
                run_id = self.client.select_preferred_instance(m.instances)
                info = self.client.get_test_info(run_id)
                result = info.result or "?"
                if not self._is_active_status(info.status):
                    print(f" - already ran: {info.status} {result}")
                    results.append(
                        TestResult(
                            test_name=m.test_module,
                            status=info.status,
                            result=info.result,
                            run_id=run_id,
                        )
                    )
                    continue
                print(f" - resuming: {info.status} {result}")
                result = self.run_single_test(plan_id, m.test_module, m.variant)
                print(f" - {result.status} {result.result or ''}")
                results.append(result)
                continue

            print(" ...", flush=True)
            result = self.run_single_test(plan_id, m.test_module, m.variant)
            print(f" - {result.status} {result.result or ''}")
            results.append(result)

        return results

    def summarize_results(self, results: list[TestResult]) -> dict[str, int]:
        summary = {"PASSED": 0, "WARNING": 0, "REVIEW": 0, "SKIPPED": 0, "FAILED": 0}
        for r in results:
            if r.status == "TIMEOUT" or r.status == "INTERRUPTED":
                summary["FAILED"] += 1
            elif r.result in summary:
                summary[r.result] += 1
            elif r.result:
                summary["FAILED"] += 1
        return summary

    def print_summary(self, results: list[TestResult]):
        summary = self.summarize_results(results)
        print("\n=== Results ===")
        for k, v in summary.items():
            print(f"{k}: {v}")

        failures = [
            r for r in results if r.result not in ("PASSED", "WARNING", "SKIPPED", "REVIEW")
        ]
        if failures:
            print("\n=== Failures ===")
            for f in failures:
                print(f"  {f.test_name}: {f.result or f.status} (ID: {f.run_id})")
