"""Wait for the public issuer and authenticated hosted suite API."""

import os
import time
from urllib.parse import urlsplit, urlunsplit

import requests
from scripts.client import ConformanceClient


def wait_until_ready(identity_url: str, suite_url: str, timeout=180, login_url: str | None = None):
    # Rust's URL serializer includes '/' for an empty root path. Match that
    # representation while preserving issuer paths, queries and fragments.
    issuer_parts = urlsplit(identity_url)
    expected_issuer = urlunsplit(issuer_parts._replace(path=issuer_parts.path or "/"))
    identity_url = identity_url.rstrip("/")
    suite_url = suite_url.rstrip("/")
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
            actual_issuer = discovery.json().get("issuer")
            if actual_issuer != expected_issuer:
                raise ValueError(
                    f"Discovery issuer mismatch: expected {expected_issuer!r}, got {actual_issuer!r}"
                )
            if login_url:
                login = requests.get(login_url.rstrip("/") + "/health/ready", timeout=10)
                login.raise_for_status()
                if login.json().get("status") != "ready":
                    raise ValueError("Login application is not ready")
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
            print(f"Waiting for conformance environment: {error}", flush=True)
            time.sleep(3)
    raise RuntimeError(f"Conformance environment did not become ready: {last_error}")


if __name__ == "__main__":
    wait_until_ready(
        os.environ["IDENTITY_URL"],
        os.environ.get("SUITE_URL", "https://localhost.emobix.co.uk:8443"),
        login_url=os.environ.get("LOGIN_URL"),
    )
