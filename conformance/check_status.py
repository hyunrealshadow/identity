#!/usr/bin/env python3
"""Check conformance test plan status."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scripts.client import ConformanceClient


def main():
    parser = argparse.ArgumentParser(description="Check plan status")
    parser.add_argument("plan_id", help="Plan ID to check")
    parser.add_argument(
        "--suite-url",
        default=os.environ.get("SUITE_URL", "https://localhost.emobix.co.uk:8443"),
        help="Conformance suite URL",
    )
    parser.add_argument("--logs", action="store_true", help="Show logs for failed tests")
    args = parser.parse_args()

    client = ConformanceClient(args.suite_url)
    modules = client.get_modules(args.plan_id)

    print(f"Plan: {args.plan_id}")
    print(f"Total modules: {len(modules)}\n")

    for m in modules:
        if m.instances:
            run_id = client.select_preferred_instance(m.instances)
            info = client.get_test_info(run_id)
            result = info.result or "?"
            status = info.status
            print(f"{m.test_module}: {result} ({status})")

            if args.logs and result in ("FAILURE", "FAILED", "WARNING"):
                logs = client.get_test_logs(run_id)
                for entry in logs:
                    if entry.get("result") in ("FAILURE", "WARNING"):
                        print(f"  {entry.get('src')}: [{entry.get('result')}] {entry.get('msg')}")
        else:
            print(f"{m.test_module}: NOT_RUN")

    print("\n=== Summary ===")
    summary = client.get_plan_summary(args.plan_id)
    for k, v in summary.items():
        print(f"{k}: {v}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
