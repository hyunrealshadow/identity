import re
import requests
from typing import Optional
from urllib.parse import urlparse, parse_qs


class AutoLoginHandler:
    def __init__(
        self,
        identity_url: str,
        username: str = "conformance-test",
        password: str = "ConformanceTest1!",
        verify_ssl: bool = False,
    ):
        self.identity_url = identity_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.docker_identity_url = "http://identity:5150"
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def reset_session(self):
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    def _localize_url(self, url: str) -> str:
        return url.replace(self.docker_identity_url, self.identity_url)

    def _complete_callback(self, callback_url: str) -> bool:
        try:
            resp = self.session.get(callback_url, allow_redirects=False)
        except Exception:
            return False

        match = re.search(r"xhr\.open\('POST',\s*['\"]([^'\"]+)['\"]", resp.text)
        if match:
            submit_url = match.group(1).replace("\\/", "/")
            try:
                self.session.post(submit_url, data="", headers={"Content-Type": "text/plain"})
            except Exception:
                return False
        return True

    def handle_auth_url(self, auth_url: str, method: str = "GET") -> bool:
        local_url = self._localize_url(auth_url)

        try:
            if method == "POST":
                parsed = urlparse(local_url)
                post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                post_body = parsed.query
                resp = self.session.post(
                    post_url,
                    data=post_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    allow_redirects=False,
                )
            else:
                resp = self.session.get(local_url, allow_redirects=False)
        except Exception:
            return False

        location = resp.headers.get("Location", "")
        if isinstance(location, list):
            location = location[0]

        if location and "login_id=" not in location and "localhost.emobix.co.uk" in location:
            return self._complete_callback(location)

        if location and "login_id=" not in location:
            if "error=" in location:
                full_loc = location if location.startswith("http") else f"{self.identity_url}{location}"
                return self._complete_callback(full_loc)
            return True

        if not location:
            return True

        match = re.search(r"login_id=([^&]+)", location)
        if not match:
            return False

        login_id = match.group(1)
        login_data = {"login_id": login_id, "username": self.username, "password": self.password}

        try:
            resp = self.session.post(
                f"{self.identity_url}/conformance/auto-login",
                json=login_data,
            )
            redirect_uri = resp.json().get("redirect_uri")
            if not redirect_uri:
                return False
        except Exception:
            return False

        return self._complete_callback(redirect_uri)

    def create_placeholder_screenshot(self) -> str:
        import base64

        placeholder_png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\xc8\x00\x00\x00\x32"
            b"\x08\x02\x00\x00\x00\x00\x00\x00\x00\x00IDATx\x9cc\xfc\xcf\xc0\x00"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return f"data:image/png;base64,{base64.b64encode(placeholder_png).decode()}"