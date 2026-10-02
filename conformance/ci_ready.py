"""Wait for the public tunnel and local official suite before creating a plan."""

import os
import time

import requests


def wait_until_ready(identity_url: str, suite_url: str, timeout=180):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            # Verify public TLS and require JSON: an Access login page is not readiness.
            discovery = requests.get(
                identity_url + "/.well-known/openid-configuration", timeout=10
            )
            discovery.raise_for_status()
            if discovery.json().get("issuer") != identity_url:
                raise ValueError("Discovery issuer does not match the public identity origin")
            suite = requests.get(suite_url + "/api/runner/available", timeout=10, verify=False)
            suite.raise_for_status()
            if not isinstance(suite.json(), list):
                raise ValueError("Official suite module API is not ready")
            # This endpoint also checks that the suite can query MongoDB.
            plans = requests.get(suite_url + "/api/plan?length=1", timeout=10, verify=False)
            plans.raise_for_status()
            plans.json()
            print("Public issuer and official suite are ready")
            return
        except (requests.RequestException, ValueError) as error:
            last_error = error
            time.sleep(3)
    raise RuntimeError(f"Conformance environment did not become ready: {last_error}")


if __name__ == "__main__":
    wait_until_ready(
        os.environ["IDENTITY_URL"],
        "https://localhost.emobix.co.uk:8443",
    )
