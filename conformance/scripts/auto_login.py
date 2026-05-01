import base64
import html
import json
import re
from urllib.parse import parse_qsl, quote, urljoin, urlparse

import requests


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
        self.host_identity_url = "http://host.docker.internal:5150"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.last_screenshot: str | None = None
        self.browser_storage_state: dict | None = None

    def reset_session(self):
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.last_screenshot = None
        self.browser_storage_state = None

    def _localize_url(self, url: str) -> str:
        return url.replace(self.docker_identity_url, self.identity_url).replace(
            self.host_identity_url,
            self.identity_url,
        )

    def _absolute_location(self, location: str) -> str:
        return self._localize_url(urljoin(f"{self.identity_url}/", location))

    def _request_authorize(self, local_url: str, method: str) -> requests.Response:
        if method == "POST":
            parsed = urlparse(local_url)
            post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return self.session.post(
                post_url,
                data=parsed.query,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=False,
            )

        return self.session.get(local_url, allow_redirects=False)

    def _login_id_from_location(self, location: str) -> str | None:
        match = re.search(r"login_id=([^&]+)", location)
        if match:
            return match.group(1)
        return None

    def _login_payload(self, login_id: str) -> dict:
        return {
            "login_id": login_id,
            "username": self.username,
            "password": self.password,
        }

    def _complete_login(self, login_id: str) -> bool:
        login_data = {
            "login_id": login_id,
            "username": self.username,
            "password": self.password,
        }

        try:
            resp = self.session.post(
                f"{self.identity_url}/conformance/auto-login",
                json=login_data,
            )
            resp.raise_for_status()
            return bool(resp.json().get("redirect_uri"))
        except Exception as exc:
            print(f"    [debug] auto-login failed: {exc}")
            return False

    def _complete_browser_login(self, context, login_id: str | None) -> str | None:
        if not login_id:
            return None

        response = context.request.post(
            f"{self.identity_url}/conformance/auto-login",
            data=json.dumps(self._login_payload(login_id)),
            headers={"Content-Type": "application/json"},
        )
        if not response.ok:
            print(f"    [debug] browser auto-login failed: HTTP {response.status}")
            return None
        redirect_uri = response.json().get("redirect_uri")
        if not redirect_uri:
            return None
        return self._localize_url(redirect_uri)

    def _post_page(self, url: str, body: str) -> str:
        fields = []
        for name, value in parse_qsl(body, keep_blank_values=True):
            fields.append(
                f'<input type="hidden" name="{html.escape(name, quote=True)}" '
                f'value="{html.escape(value, quote=True)}">'
            )
        return (
            "<!doctype html><html><body>"
            f'<form id="f" method="post" action="{html.escape(url, quote=True)}">'
            f"{''.join(fields)}</form>"
            "</body></html>"
        )

    def _submit_post_form(self, page, url: str, body: str) -> None:
        page.set_content(self._post_page(url, body), wait_until="load")
        page.locator("#f").evaluate("form => form.submit()")
        page.wait_for_load_state("load", timeout=30_000)

    def _uses_form_post(self, url: str) -> bool:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if any(
            name == "response_mode" and value == "form_post"
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ):
            return True

        request_object = params.get("request")
        if not request_object:
            return False

        parts = request_object.split(".")
        if len(parts) < 2:
            return False

        try:
            payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_segment))
        except Exception:
            return False

        return payload.get("response_mode") == "form_post"

    def _complete_redirect_in_browser(self, page, redirect_uri: str, form_post: bool) -> None:
        parsed = urlparse(redirect_uri)
        if not form_post:
            page.goto(redirect_uri, wait_until="load", timeout=30_000)
            return

        action = parsed._replace(query="", fragment="").geturl()
        body = parsed.query or parsed.fragment
        self._submit_post_form(page, action, body)

    @staticmethod
    def _screenshot_data_url(page) -> str:
        image = page.screenshot(full_page=True)
        return f"data:image/png;base64,{base64.b64encode(image).decode()}"

    def _complete_in_browser(
        self,
        local_url: str,
        method: str = "GET",
        login_id: str | None = None,
    ) -> bool:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("    [debug] playwright is not installed; run via `uv run`")
            return False

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context_args = {"ignore_https_errors": True}
                if self.browser_storage_state:
                    context_args["storage_state"] = self.browser_storage_state
                context = browser.new_context(**context_args)
                page = context.new_page()

                form_post = self._uses_form_post(local_url)
                if method == "POST":
                    parsed = urlparse(local_url)
                    post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    self._submit_post_form(page, post_url, parsed.query)
                else:
                    page.goto(local_url, wait_until="load", timeout=30_000)

                try:
                    page.wait_for_load_state("networkidle", timeout=10_000)
                except PlaywrightTimeoutError:
                    pass

                current_login_id = login_id or self._login_id_from_location(page.url)
                if current_login_id:
                    redirect_uri = self._complete_browser_login(context, current_login_id)
                    if not redirect_uri:
                        browser.close()
                        return False
                    self._complete_redirect_in_browser(page, redirect_uri, form_post)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10_000)
                    except PlaywrightTimeoutError:
                        pass

                page.wait_for_timeout(2_000)
                self.last_screenshot = self._screenshot_data_url(page)
                self.browser_storage_state = context.storage_state()
                browser.close()
                return True
        except Exception as exc:
            print(f"    [debug] browser auth failed: {exc}")
            return False

    def screenshot_url(self, url: str, method: str = "GET") -> str | None:
        local_url = self._localize_url(url)
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("    [debug] playwright is not installed; run via `uv run`")
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                if method == "POST":
                    parsed = urlparse(local_url)
                    post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    self._submit_post_form(page, post_url, parsed.query)
                else:
                    page.goto(local_url, wait_until="load", timeout=30_000)

                try:
                    page.wait_for_load_state("networkidle", timeout=10_000)
                except PlaywrightTimeoutError:
                    pass
                page.wait_for_timeout(1_000)
                screenshot = self._screenshot_data_url(page)
                self.last_screenshot = screenshot
                browser.close()
                return screenshot
        except Exception as exc:
            print(f"    [debug] browser screenshot failed: {exc}")
            return None

    def handle_auth_url(self, auth_url: str, method: str = "GET") -> bool:
        local_url = self._localize_url(auth_url)
        return self._complete_in_browser(local_url, method)

    def screenshot_for_upload(self, urls: list[str], method: str = "GET") -> str | None:
        if self.last_screenshot:
            return self.last_screenshot

        if not urls:
            return None

        return self.screenshot_url(urls[-1], method)
