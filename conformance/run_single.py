#!/usr/bin/env python3
"""Run a single conformance test module."""

import argparse
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scripts.client import ConformanceClient
from scripts.auto_login import AutoLoginHandler
from scripts.runner import TestRunner


def main():
    parser = argparse.ArgumentParser(description="Run single test")
    parser.add_argument("--plan-id", required=True, help="Plan ID")
    parser.add_argument("--test", required=True, help="Test module name")
    parser.add_argument(
        "--variant",
        default='{"client_auth_type":"client_secret_basic","response_type":"code","response_mode":"default"}',
        help="Test variant JSON",
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
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")
    args = parser.parse_args()

    client = ConformanceClient(args.suite_url)
    auto_login = AutoLoginHandler(args.identity_url)
    runner = TestRunner(client, auto_login, timeout_per_test=args.timeout)

    variant = json.loads(args.variant)
    result = runner.run_single_test(args.plan_id, args.test, variant)

    print(f"\nResult: {result.status} {result.result or ''}")
    print(f"Run ID: {result.run_id}")

    if result.result not in ("PASSED", "WARNING", "SKIPPED"):
        logs = client.get_test_logs(result.run_id)
        print("\nLogs:")
        for entry in logs:
            if entry.get("result") in ("FAILURE", "WARNING"):
                print(f"  {entry.get('src')}: [{entry.get('result')}] {entry.get('msg')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
