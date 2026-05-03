#!/usr/bin/env python3
"""
OpenID Connect Conformance Test Runner

Usage:
    python run.py                    # Run full test suite
    python run.py --plan-id <ID>     # Run tests on existing plan
    python run.py --check <ID>       # Check plan status only
    python run.py --help             # Show help

Environment variables:
    SUITE_URL        - Conformance suite URL (default: https://localhost.emobix.co.uk:8443)
    IDENTITY_URL     - Identity server URL (default: https://localhost:5150)
    PROFILE          - Profile to create: basic, implicit, hybrid, config, formpost-basic, formpost-implicit, or formpost-hybrid (default: basic)
    CONFIG_PATH      - Config file path (default: conformance/plans/<profile>.json)
    PLAN_NAME        - Conformance suite plan name (default derived from PROFILE)
    TIMEOUT          - Timeout per test in seconds (default: 60)
"""

import argparse
import os
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

import subprocess
import time
import json
import signal

try:
    import requests
except ImportError:
    print("ERROR: requests module not installed. Run: pip install requests")
    sys.exit(1)

from scripts.client import ConformanceClient
from scripts.browser_auth import BrowserAuthHandler
from scripts.runner import TestRunner


DEFAULT_PLAN_VARIANT = {
    "server_metadata": "discovery",
    "client_registration": "static_client",
}

SUPPORTED_PROFILES = (
    "basic",
    "implicit",
    "hybrid",
    "config",
    "formpost-basic",
    "formpost-implicit",
    "formpost-hybrid",
)

PLAN_NAMES = {
    "basic": "oidcc-basic-certification-test-plan",
    "implicit": "oidcc-implicit-certification-test-plan",
    "hybrid": "oidcc-hybrid-certification-test-plan",
    "config": "oidcc-config-certification-test-plan",
    "formpost-basic": "oidcc-formpost-basic-certification-test-plan",
    "formpost-implicit": "oidcc-formpost-implicit-certification-test-plan",
    "formpost-hybrid": "oidcc-formpost-hybrid-certification-test-plan",
}


def default_plan_name_for_profile(profile: str):
    return PLAN_NAMES[profile]


def plan_variant_for_profile(profile: str):
    if profile == "config":
        return None
    return DEFAULT_PLAN_VARIANT.copy()


def wait_for_service(url: str, timeout: int = 120, name: str = "service") -> bool:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code < 500:
                print(f"{name} is ready")
                return True
        except Exception:
            pass
        time.sleep(2)
    print(f"ERROR: {name} not ready after {timeout}s")
    return False


def start_docker_stack(compose_file: str) -> bool:
    print("Starting Docker stack...")
    result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d", "--build"],
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"ERROR: Docker compose failed: {result.stderr.decode()}")
        return False
    return True


def stop_docker_stack(compose_file: str):
    print("Stopping Docker stack...")
    subprocess.run(["docker", "compose", "-f", compose_file, "down"], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description="OpenID Connect Conformance Test Runner")
    parser.add_argument("--plan-id", help="Existing plan ID to run tests on")
    parser.add_argument("--check", help="Check status of plan ID only")
    parser.add_argument(
        "--profile",
        choices=SUPPORTED_PROFILES,
        default=os.environ.get("PROFILE", "basic"),
        help="Conformance profile to create when --plan-id is not provided",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("CONFIG_PATH"),
        help="Plan config JSON path. Defaults to conformance/plans/<profile>.json",
    )
    parser.add_argument(
        "--plan-name",
        default=os.environ.get("PLAN_NAME"),
        help="Conformance suite plan name. Defaults from --profile",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Don't start/stop Docker (services already running)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("TIMEOUT", "60")),
        help="Timeout per test in seconds",
    )
    parser.add_argument(
        "--suite-url",
        default=os.environ.get("SUITE_URL", "https://localhost.emobix.co.uk:8443"),
        help="Conformance suite URL",
    )
    parser.add_argument(
        "--identity-url",
        default=os.environ.get("IDENTITY_URL", "https://localhost:5150"),
        help="Identity server URL",
    )
    parser.add_argument(
        "--exit-on-failure",
        action="store_true",
        help="Exit with error code if any tests fail",
    )
    args = parser.parse_args()

    compose_file = os.path.join(script_dir, "docker-compose.yml")
    if args.profile not in PLAN_NAMES:
        parser.error("--profile must be one of: basic, implicit, hybrid")
    config_path = args.config or os.path.join(script_dir, "plans", f"{args.profile}.json")
    plan_name = args.plan_name or default_plan_name_for_profile(args.profile)

    if args.check:
        client = ConformanceClient(args.suite_url)
        summary = client.get_plan_summary(args.check)
        print(f"\nPlan {args.check} status:")
        for k, v in summary.items():
            print(f"  {k}: {v}")
        return 0

    if not args.no_docker:
        if not start_docker_stack(compose_file):
            return 1

        def cleanup(signum, frame):
            stop_docker_stack(compose_file)
            sys.exit(1)

        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)

        if not wait_for_service(args.identity_url + "/health", timeout=60, name="Identity"):
            stop_docker_stack(compose_file)
            return 1
        if not wait_for_service(args.suite_url, timeout=120, name="Conformance Suite"):
            stop_docker_stack(compose_file)
            return 1

    client = ConformanceClient(args.suite_url)
    auto_login = BrowserAuthHandler(args.identity_url)
    runner = TestRunner(client, auto_login, timeout_per_test=args.timeout)

    if args.plan_id:
        plan_id = args.plan_id
    else:
        print(f"Creating {args.profile} test plan...")
        plan_id = client.create_plan(
            config_path,
            plan_name=plan_name,
            variant=plan_variant_for_profile(args.profile),
        )
        print(f"Plan ID: {plan_id}")

    print(f"\nRunning tests...")
    results = runner.run_all_tests(plan_id)
    runner.print_summary(results)

    if not args.no_docker:
        stop_docker_stack(compose_file)

    if args.exit_on_failure:
        failures = [r for r in results if r.result not in ("PASSED", "WARNING", "SKIPPED", "REVIEW")]
        if failures:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
