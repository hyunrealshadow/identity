"""Wait for the public issuer and authenticated hosted suite API."""

import os
import time

import requests
from scripts.client import ConformanceClient


def wait_until_ready(identity_url: str, suite_url: str, timeout=180):
    client = ConformanceClient(suite_url)
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
            suite = client.session.get(suite_url + "/api/runner/available", timeout=10)
            suite.raise_for_status()
            if not isinstance(suite.json(), list):
                raise ValueError("Official suite module API is not ready")
            account = client.session.get(suite_url + "/api/currentuser", timeout=10)
            account.raise_for_status()
            account.json()
            print("Public issuer and official suite are ready")
            return
        except (requests.RequestException, ValueError) as error:
            last_error = error
            time.sleep(3)
    raise RuntimeError(f"Conformance environment did not become ready: {last_error}")


if __name__ == "__main__":
    wait_until_ready(
        os.environ["IDENTITY_URL"],
        os.environ.get("SUITE_URL", "https://localhost.emobix.co.uk:8443"),
    )
