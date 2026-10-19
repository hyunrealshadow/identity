"""Publish a hosted CI plan, including failed or interrupted runs."""

import argparse
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen


def publish_results(results_dir=Path("conformance/results")):
    plan_file = results_dir / "plan-url.txt"
    if not plan_file.exists():
        print("No plan was created; skipping publication.")
        return

    suite_url = os.environ["SUITE_URL"].rstrip("/")
    plan_url = urlsplit(plan_file.read_text().strip())
    suite = urlsplit(suite_url)
    if (plan_url.scheme, plan_url.netloc) != (suite.scheme, suite.netloc):
        raise ValueError("Plan URL does not belong to the configured suite")
    plan_id = parse_qs(plan_url.query)["plan"][0]
    request = Request(
        f"{suite_url}/api/plan/{quote(plan_id, safe='')}/publish",
        data=json.dumps({"publish": "everything"}).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['CONFORMANCE_API_TOKEN']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=60) as response:
        response.read()

    public_url = f"{suite_url}/plan-detail.html?plan={quote(plan_id, safe='')}&public=true"
    plan_file.write_text(public_url + "\n")
    report_file = results_dir / "results.json"
    if report_file.exists():
        report = json.loads(report_file.read_text())
        report["plan_url"] = public_url
        report_file.write_text(json.dumps(report, indent=2))
    print(f"Published official plan: {public_url}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("conformance/results"))
    publish_results(parser.parse_args().results_dir)
