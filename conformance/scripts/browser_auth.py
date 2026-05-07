import base64
import html
import re
from urllib.parse import parse_qsl, urlencode, urlparse


class BrowserAuthHandler:
    def __init__(self, identity_url: str):
        self.identity_url = identity_url.rstrip("/")
        self.docker_identity_url = "https://identity:5150"
        self.host_identity_url = "https://host.docker.internal:5150"
        self.last_screenshot: str | None = None
        self.browser_storage_state: dict | None = None

    def reset_session(self):
        self.last_screenshot = None
        self.browser_storage_state = None

    def _localize_url(self, url: str) -> str:
        return url

    def _chromium_launch_args(self) -> list[str]:
        return [
            "--host-resolver-rules=MAP identity 127.0.0.1,MAP host.docker.internal 127.0.0.1"
        ]

    def _login_id_from_location(self, location: str) -> str | None:
        match = re.search(r"login_id=([^&]+)", location)
        if match:
            return match.group(1)
        return None

    def _op_browser_url(self, page_url: str) -> str:
        parsed = urlparse(page_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return self.identity_url

    def _auto_login_page_url(self, login_id: str, op_browser_url: str) -> str:
        return f"{op_browser_url}/conformance/auto-login?{urlencode({'login_id': login_id})}"

    def _continue_url(self, login_id: str, op_browser_url: str) -> str:
        return f"{op_browser_url}/oauth2/continue?{urlencode({'login_id': login_id})}"

    def _complete_browser_login(self, page, login_id: str | None) -> bool:
        if not login_id:
            return False

        op_browser_url = self._op_browser_url(page.url)
        page.goto(
            self._auto_login_page_url(login_id, op_browser_url),
            wait_until="load",
            timeout=30_000,
        )
        page.wait_for_load_state("load", timeout=30_000)
        page.goto(
            self._continue_url(login_id, op_browser_url),
            wait_until="load",
            timeout=30_000,
        )
        page.wait_for_load_state("load", timeout=30_000)
        return True

    def _submit_post_form(self, page, url: str, body: str) -> None:
        fields = []
        for name, value in parse_qsl(body, keep_blank_values=True):
            fields.append(
                f'<input type="hidden" name="{html.escape(name, quote=True)}" '
                f'value="{html.escape(value, quote=True)}">'
            )
        page.set_content(
            "<!doctype html><html><body>"
            f'<form id="f" method="post" action="{html.escape(url, quote=True)}">'
            f"{''.join(fields)}</form>"
            "<script>document.getElementById('f').submit()</script>"
            "</body></html>",
            wait_until="load",
        )
        page.wait_for_load_state("load", timeout=30_000)

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
                browser = p.chromium.launch(headless=True, args=self._chromium_launch_args())
                context_args = {"ignore_https_errors": True}
                if self.browser_storage_state:
                    context_args["storage_state"] = self.browser_storage_state
                context = browser.new_context(**context_args)
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

                current_login_id = login_id or self._login_id_from_location(page.url)
                if current_login_id:
                    if not self._complete_browser_login(page, current_login_id):
                        browser.close()
                        return False
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

    def handle_auth_url(self, auth_url: str, method: str = "GET") -> bool:
        local_url = self._localize_url(auth_url)
        return self._complete_in_browser(local_url, method)

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
                browser = p.chromium.launch(headless=True, args=self._chromium_launch_args())
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

    def screenshot_for_upload(self, urls: list[str], method: str = "GET") -> str | None:
        if self.last_screenshot:
            return self.last_screenshot

        if not urls:
            return None

        return self.screenshot_url(urls[-1], method)
