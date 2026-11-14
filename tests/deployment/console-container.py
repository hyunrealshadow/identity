"""Exercise a built Console image without production services or credentials."""
import http.server
import json
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def verify(image):
    token = secrets.token_urlsafe(36)
    config = {
        "issuer": "https://identity.example/",
        "graphqlUrl": "https://identity.example/graphql",
        "clientId": "public-console",
        "redirectUri": "https://login.example/console/callback",
        "postLogoutRedirectUri": "https://login.example/console/logout",
        "accountUrl": "https://login.example/account",
        "scope": "openid profile email management.*",
        "displayName": 'Console "测试"',
        "environment": "test",
    }
    payload = config
    transient_failures = 2
    accepted = {"token": token}
    forwarded = {}

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal transient_failures
            if self.path != "/internal/workloads/self/runtime-configuration":
                self.send_error(404)
                return
            forwarded.update(cookie=self.headers.get("Cookie"), agent=self.headers.get("User-Agent"))
            if self.headers.get("Authorization") != f"Bearer {accepted['token']}":
                self.send_error(401)
                return
            if transient_failures:
                transient_failures -= 1
                self.send_response(404 if transient_failures == 1 else 503)
                self.end_headers()
                return
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    upstream = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    container = None
    try:
        with tempfile.TemporaryDirectory(prefix="identity-console-") as temporary:
            credential = Path(temporary) / "workload-token"
            credential.write_bytes((token + "\r\n").encode())
            credential.chmod(0o444)
            args = [
                "--read-only", "--tmpfs", "/tmp",
                "--tmpfs", "/run/identity-console:mode=1777",
                "--add-host", "host.docker.internal:host-gateway",
                "--mount", f"type=bind,source={credential},target=/run/secrets/console-token,readonly",
                "-e", "IDENTITY_WORKLOAD_TOKEN_FILE=/run/secrets/console-token",
                "-e", f"IDENTITY_INTERNAL_API_URL=http://host.docker.internal:{upstream.server_port}",
            ]
            container = docker("run", "-d", *args, "-e", "IDENTITY_INTERNAL_API_ALLOW_HTTP=true",
                               "-p", "127.0.0.1::8080", image).stdout.strip()
            port = docker("port", container, "8080/tcp").stdout.strip().split(":")[-1]
            origin = f"http://127.0.0.1:{port}"
            for _ in range(150):
                try:
                    response = urllib.request.urlopen(origin + "/console/config.json", timeout=1)
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.2)
            else:
                raise AssertionError("Console did not start")
            assert json.load(response) == config

            # config.json is proxied on every request: a changed Identity
            # response is visible without restarting the container.
            def fetch_config():
                request = urllib.request.Request(
                    origin + "/console/config.json",
                    headers={"Cookie": "session=must-not-be-forwarded", "User-Agent": "browser"},
                )
                return urllib.request.urlopen(request, timeout=5)
            payload = {**config, "clientId": "Q2xpZW50OgAAAAAAAAAAAAAAAAAAAAA"}
            with fetch_config() as refreshed:
                assert json.load(refreshed) == payload
                assert refreshed.headers["Cache-Control"] == "no-store"
            assert forwarded["cookie"] is None and forwarded["agent"] != "browser"

            # A rotated credential file is read on the next request.
            rotated = secrets.token_urlsafe(36)
            credential.chmod(0o644)
            credential.write_bytes((rotated + "\n").encode())
            credential.chmod(0o444)
            accepted["token"] = rotated
            with fetch_config() as after_rotation:
                assert json.load(after_rotation) == payload

            # Anything other than the exact Console fields is withheld.
            payload = {"oauth_client": {"client_secret": "must-not-be-published"}}
            try:
                fetch_config()
                raise AssertionError("Unexpected runtime configuration was published")
            except urllib.error.HTTPError as error:
                assert error.code == 503
                assert "must-not-be-published" not in error.read().decode()
                assert error.headers["Cache-Control"] == "no-store"
            accepted["token"] = "not-the-console-credential-0123456789"
            try:
                fetch_config()
                raise AssertionError("Rejected credential still produced a configuration")
            except urllib.error.HTTPError as error:
                assert error.code == 503
            accepted["token"] = rotated
            payload = config
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            try:
                urllib.request.build_opener(NoRedirect()).open(origin + "/console/?tab=1")
                raise AssertionError("Expected Console slash redirect")
            except urllib.error.HTTPError as redirect:
                assert redirect.code == 308
                assert redirect.headers["Location"] == "/console?tab=1"
            with urllib.request.build_opener(NoRedirect()).open(origin + "/console") as home:
                assert home.status == 200
                assert "<!doctype html" in home.read().decode().lower()
                assert home.headers["Cache-Control"] == "no-cache"
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["X-Frame-Options"] == "DENY"
            # Readiness probes use the Pod address, not the installed public host.
            request = urllib.request.Request(origin + "/health/ready", headers={"Host": "10.42.0.10:8080"})
            with urllib.request.urlopen(request) as ready:
                assert ready.status == 200
                assert ready.read() == b"ok\n"
            assert docker("exec", container, "id", "-u").stdout.strip() != "0"
            assert docker("exec", container, "curl", "--fail", "--silent",
                          "http://127.0.0.1:8081/health").stdout.strip() == "ok"
            with urllib.request.urlopen(origin + "/console/users/example/roles") as response:
                html = response.read().decode()
                assert "<!doctype html" in html.lower()
                assert response.headers["Cache-Control"] == "no-cache"
            asset = re.search(r'(?:src|href)="(/console/assets/[^\"]+)"', html).group(1)
            with urllib.request.urlopen(origin + asset) as response:
                assert "immutable" in response.headers["Cache-Control"]
            try:
                urllib.request.urlopen(origin + "/console/assets/absent.js")
                raise AssertionError("Missing asset incorrectly returned the SPA document")
            except urllib.error.HTTPError as error:
                assert error.code == 404
                assert error.headers["Cache-Control"] == "no-store"
            with urllib.request.urlopen(origin + "/console/callback?code=must-not-be-logged&state=private") as response:
                assert response.status == 200
            logs = docker("logs", container)
            assert '"path":"/health/ready"' not in logs.stdout
            assert token not in logs.stdout + logs.stderr
            assert rotated not in logs.stdout + logs.stderr
            assert "must-not-be-published" not in logs.stdout + logs.stderr
            assert "must-not-be-logged" not in logs.stdout + logs.stderr
            assert docker("exec", container, "sh", "-c",
                          "test ! -e /usr/share/nginx/html/console/config.json "
                          "&& test ! -e /run/identity-console/config.json").returncode == 0
            docker("stop", "--time", "3", container)
            docker("rm", container)
            container = None

            # The same read-only/non-root image can terminate TLS on a custom port.
            certificate = Path(temporary) / "console.crt"
            private_key = Path(temporary) / "console.key"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout", str(private_key), "-out", str(certificate),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            certificate.chmod(0o444)
            private_key.chmod(0o444)
            tls_args = [
                *args, "-e", "IDENTITY_INTERNAL_API_ALLOW_HTTP=true",
                "-e", "IDENTITY_CONSOLE_TLS_ENABLED=true", "-e", "PORT=8443",
                "--mount", f"type=bind,source={certificate},target=/etc/identity/console-tls/tls.crt,readonly",
                "--mount", f"type=bind,source={private_key},target=/etc/identity/console-tls/tls.key,readonly",
            ]
            container = docker("run", "-d", *tls_args, "-p", "127.0.0.1::8443", image).stdout.strip()
            port = docker("port", container, "8443/tcp").stdout.strip().split(":")[-1]
            origin = f"https://127.0.0.1:{port}"
            context = ssl.create_default_context(cafile=str(certificate))
            for _ in range(100):
                try:
                    response = urllib.request.urlopen(origin + "/console/config.json", context=context, timeout=1)
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.2)
            else:
                raise AssertionError("TLS Console did not start")
            assert json.load(response) == config
            with urllib.request.urlopen(origin + "/health/ready", context=context) as ready:
                assert ready.read() == b"ok\n"
            with urllib.request.urlopen(origin + "/console/users/example/roles", context=context) as response:
                assert "<!doctype html" in response.read().decode().lower()
            try:
                urllib.request.urlopen(origin + "/health/ready", timeout=2)
                raise AssertionError("Untrusted serving certificate was accepted")
            except urllib.error.URLError as error:
                assert isinstance(error.reason, ssl.SSLCertVerificationError)
            assert docker("exec", container, "curl", "--fail", "--silent",
                          "http://127.0.0.1:8081/health").stdout.strip() == "ok"
            docker("stop", "--time", "3", container)
            docker("rm", container)
            container = None

            missing_tls = docker("run", "--rm", *args, "-e", "IDENTITY_CONSOLE_TLS_ENABLED=true",
                                 image, check=False)
            assert missing_tls.returncode != 0
            assert "readable certificate and private key" in missing_tls.stderr
            mismatched_key = Path(temporary) / "mismatched.key"
            subprocess.run(["openssl", "genrsa", "-out", str(mismatched_key), "2048"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            mismatched_key.chmod(0o444)
            rejected = docker("run", "--rm", *args, "-e", "IDENTITY_CONSOLE_TLS_ENABLED=true",
                              "--mount", f"type=bind,source={certificate},target=/etc/identity/console-tls/tls.crt,readonly",
                              "--mount", f"type=bind,source={mismatched_key},target=/etc/identity/console-tls/tls.key,readonly",
                              image, check=False)
            assert rejected.returncode != 0
            assert "key values mismatch" in rejected.stderr

            # Startup rejects HTTP unless explicitly allowed.
            rejected = docker("run", "--rm", *args, image, check=False)
            assert rejected.returncode != 0
            payload = {"oauth_client": {"client_secret": "must-not-be-published"}}
            rejected = docker("run", "--rm", *args, "-e", "IDENTITY_INTERNAL_API_ALLOW_HTTP=true",
                              image, check=False)
            assert rejected.returncode != 0
            assert "must-not-be-published" not in rejected.stdout + rejected.stderr
            assert token not in rejected.stdout + rejected.stderr
    except Exception:
        if container:
            logs = docker("logs", container, check=False)
            print((logs.stdout + logs.stderr).replace(token, "[redacted]")
                  .replace(accepted["token"], "[redacted]"), file=sys.stderr)
        raise
    finally:
        if container:
            docker("rm", "-f", container, check=False)
        upstream.shutdown()
        upstream.server_close()
    print("Console HTTP/HTTPS startup, proxied configuration refresh, credential rotation, custom port, "
          "certificate validation, routing, caching and failure handling passed")


if __name__ == "__main__":
    verify(sys.argv[1])
