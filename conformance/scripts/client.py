import json
import urllib.parse
import requests
from typing import Optional
from dataclasses import dataclass


@dataclass
class TestModule:
    test_module: str
    variant: dict
    instances: list[str]
    test_summary: str


@dataclass
class TestInfo:
    id: str
    status: str
    result: Optional[str]


class ConformanceClient:
    def __init__(self, suite_url: str, verify_ssl: bool = False):
        self.suite_url = suite_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def create_plan(
        self,
        config_path: str,
        plan_name: str = "oidcc-basic-certification-test-plan",
        variant: Optional[dict] = None,
    ) -> str:
        with open(config_path, "r") as f:
            config = json.load(f)

        if variant is None:
            variant = {"server_metadata": "discovery", "client_registration": "static_client"}

        variant_encoded = urllib.parse.quote(json.dumps(variant))
        url = f"{self.suite_url}/api/plan?planName={plan_name}&variant={variant_encoded}"

        resp = self.session.post(url, json=config)
        resp.raise_for_status()
        plan = resp.json()
        return plan["id"]

    def get_plan(self, plan_id: str) -> dict:
        resp = self.session.get(f"{self.suite_url}/api/plan/{plan_id}")
        resp.raise_for_status()
        return resp.json()

    def get_modules(self, plan_id: str) -> list[TestModule]:
        plan = self.get_plan(plan_id)
        modules = []
        for m in plan.get("modules", []):
            modules.append(
                TestModule(
                    test_module=m["testModule"],
                    variant=m["variant"],
                    instances=m.get("instances", []),
                    test_summary=m.get("testSummary", ""),
                )
            )
        return modules

    def start_test(self, plan_id: str, test_name: str, variant: dict) -> str:
        variant_encoded = urllib.parse.quote(json.dumps(variant))
        url = f"{self.suite_url}/api/runner?test={test_name}&plan={plan_id}&variant={variant_encoded}"
        resp = self.session.post(url)
        resp.raise_for_status()
        return resp.json()["id"]

    def get_test_info(self, run_id: str) -> TestInfo:
        resp = self.session.get(f"{self.suite_url}/api/info/{run_id}")
        resp.raise_for_status()
        data = resp.json()
        return TestInfo(id=run_id, status=data["status"], result=data.get("result"))

    def get_test_status(self, run_id: str) -> dict:
        resp = self.session.get(f"{self.suite_url}/api/runner/{run_id}")
        resp.raise_for_status()
        return resp.json()

    def get_browser_urls(self, run_id: str) -> list[str]:
        resp = self.session.get(f"{self.suite_url}/api/runner/browser/{run_id}")
        resp.raise_for_status()
        return resp.json().get("urls", [])

    def get_test_logs(self, run_id: str) -> list[dict]:
        resp = self.session.get(f"{self.suite_url}/api/log/{run_id}")
        resp.raise_for_status()
        return resp.json()

    def get_pending_screenshots(self, run_id: str) -> list[dict]:
        resp = self.session.get(f"{self.suite_url}/api/log/{run_id}/images")
        resp.raise_for_status()
        return resp.json()

    def upload_screenshot(self, run_id: str, upload_id: str, image_data: str) -> bool:
        resp = self.session.post(
            f"{self.suite_url}/api/log/{run_id}/images/{upload_id}",
            data=image_data,
            headers={"Content-Type": "text/plain"},
        )
        return resp.status_code == 200

    def get_plan_summary(self, plan_id: str) -> dict[str, int]:
        modules = self.get_modules(plan_id)
        summary = {"PASSED": 0, "WARNING": 0, "REVIEW": 0, "SKIPPED": 0, "FAILED": 0, "PENDING": 0}
        for m in modules:
            if not m.instances:
                summary["PENDING"] += 1
            else:
                info = self.get_test_info(m.instances[0])
                result = info.result or "FAILED"
                if result in summary:
                    summary[result] += 1
                else:
                    summary["FAILED"] += 1
        return summary