"""Read the public Quick Tunnel URL before starting identity with that issuer."""

import re
import subprocess
import time


def public_url_from_logs(logs: str) -> str | None:
    # Match the success table, not an API URL mentioned in a provisioning error.
    marker = "Your quick Tunnel has been created!"
    if marker not in logs:
        return None
    startup = logs.split(marker, 1)[1]
    match = re.search(
        r"\|\s*(https://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.trycloudflare\.com)\s*\|",
        startup,
    )
    return match.group(1) if match else None


def wait_for_tunnel_url(timeout: int = 120) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "compose", "logs", "--no-color", "tunnel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        url = public_url_from_logs(result.stdout + result.stderr)
        if url:
            return url
        time.sleep(2)
    raise RuntimeError("Cloudflare did not allocate a Quick Tunnel hostname within the timeout")


if __name__ == "__main__":
    print(wait_for_tunnel_url())
