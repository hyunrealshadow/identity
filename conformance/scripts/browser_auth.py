import base64
import html
import json
import os
from pathlib import Path
from uuid import uuid4
from urllib.parse import parse_qs, parse_qsl, urlparse


# These match the two accounts seeded only in APP_ENV=conformance.
TEST_ACCOUNTS = (
    ("conformance-test", "conformance-test@example.com", "ConformanceTest1!"),
    ("conformance-test-2", "conformance-test-2@example.com", "ConformanceTest2!"),
)


class BrowserAuthHandler:
    def __init__(self, identity_url: str, login_url: str | None = None):
        self.identity_url = identity_url.rstrip("/")
        self.login_url = (
            login_url or os.environ.get("LOGIN_URL", "https://localhost:3000")
        ).rstrip("/")
        self.last_screenshot: str | None = None
        self.browser_storage_state: dict | None = None
        self.login_prompt_screenshot: str | None = None
        self.error_page_screenshot: str | None = None
        self.account_index = 0
        self.artifacts_dir = os.environ.get("CONFORMANCE_BROWSER_ARTIFACTS_DIR")

    def reset_session(self):
        self.last_screenshot = None
        self.browser_storage_state = None
        self.login_prompt_screenshot = None
        self.error_page_screenshot = None
        self.account_index = 0

    def _observe_authorization(self, request) -> None:
        parsed = urlparse(request.url)
        if parsed.path != "/oauth2/authorize":
            return
        if (parsed.scheme, parsed.netloc) not in {
            (urlparse(self.identity_url).scheme, urlparse(self.identity_url).netloc),
            ("https", "identity:5150"),
        }:
            return
        query = parse_qs(parsed.query)
        hint = query.get("login_hint", [None])[0]
        for index, (username, email, _) in enumerate(TEST_ACCOUNTS):
            if hint in (username, email):
                self.account_index = index
                return
        if "select_account" in query.get("prompt", [""])[0].split():
            self.account_index = 1 - self.account_index

    def _drive_interactions(self, page) -> None:
        """Submit the real Login application's forms, including their CSRF fields."""
        login_origin = urlparse(self.login_url)
        for _ in range(12):
            current = urlparse(page.url)
            if (current.scheme, current.netloc) != (login_origin.scheme, login_origin.netloc):
                return
            path = current.path.rstrip("/")
            if path not in ("/login", "/login/password", "/consent"):
                raise RuntimeError(f"Unsupported login interaction: {path}")

            username, email, password = TEST_ACCOUNTS[self.account_index]
            previous_url = page.url
            if path == "/login":
                identifier = page.locator('input[name="identifier"]')
                if identifier.is_visible():
                    self.login_prompt_screenshot = self._screenshot_data_url(page)
                    identifier.fill(username)
                    submit = page.locator('form:has(input[name="identifier"]) button[type="submit"]')
                else:
                    account = page.locator('form:has(input[name="intent"][value="select"])').filter(has_text=email)
                    if account.count():
                        submit = account.locator('button[type="submit"]')
                    else:
                        # The standard account picker exposes this link for signing
                        # in another account without clearing the current sessions.
                        submit = page.locator('a[href*="no_accounts=1"]')
            elif path == "/login/password":
                credential = page.locator('input[name="credential"]')
                credential.wait_for(state="visible", timeout=15_000)
                # A freshness challenge can already be bound to an OP session.
                # Authenticate the account displayed by the standard UI.
                for index, (_, account_email, account_password) in enumerate(TEST_ACCOUNTS):
                    if page.get_by_text(account_email, exact=True).is_visible():
                        self.account_index = index
                        password = account_password
                        break
                self.login_prompt_screenshot = self._screenshot_data_url(page)
                credential.fill(password)
                submit = page.locator('form:has(input[name="credential"]) button[type="submit"]')
            else:
                submit = page.locator('button[name="decision"][value="approve"]')

            print(f"    [browser] {path}, account={username}", flush=True)
            submit.click(timeout=15_000)
            page.wait_for_url(lambda url: str(url) != previous_url, wait_until="load", timeout=30_000)
            self._assert_page_loaded(page)
        raise RuntimeError("Login interaction exceeded the step limit")

    def _localize_url(self, url: str) -> str:
        return url

    def _chromium_launch_args(self) -> list[str]:
        return [
            "--host-resolver-rules=MAP identity 127.0.0.1,MAP host.docker.internal 127.0.0.1"
        ]

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
        image = page.screenshot(full_page=True, animations="disabled")
        return f"data:image/png;base64,{base64.b64encode(image).decode()}"

    @staticmethod
    def _assert_page_loaded(page, response=None) -> None:
        if response is not None and response.status >= 500:
            raise RuntimeError(
                f"browser navigation failed with HTTP {response.status}: {page.url}"
            )

        content = page.content()
        if "Blocked request. This host" in content:
            raise RuntimeError(f"Vite rejected browser host for {page.url}")

    def _save_browser_failure(self, page, context, error) -> None:
        if not self.artifacts_dir:
            return
        try:
            destination = Path(self.artifacts_dir) / f"failure-{uuid4().hex}"
            destination.mkdir(parents=True, exist_ok=True)
            # Diagnostic artifacts must never become certification UI evidence.
            (destination / "failure.json").write_text(
                json.dumps({"url": page.url, "error": str(error)}, indent=2),
                encoding="utf-8",
            )
            for name, capture in (
                ("page.txt", lambda: (destination / "page.txt").write_text(
                    page.locator("body").inner_text(timeout=3000), encoding="utf-8"
                )),
                ("page.png", lambda: page.screenshot(path=str(destination / "page.png"), full_page=True, timeout=3000)),
                ("trace.zip", lambda: context.tracing.stop(path=str(destination / "trace.zip"))),
            ):
                try:
                    capture()
                except Exception as capture_error:
                    print(f"    [debug] could not save {name}: {capture_error}")
            print(f"    [debug] browser failure artifacts: {destination}", flush=True)
        except Exception as capture_error:
            print(f"    [debug] could not save browser failure artifacts: {capture_error}")

    def _complete_in_browser(
        self,
        local_url: str,
        method: str = "GET",
    ) -> bool:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("    [debug] playwright is not installed; run via `uv run`")
            return False

        try:
            with sync_playwright() as p:
                # Evidence must belong to this browser interaction, never a prior
                # authorization that happened to display a password prompt.
                self.login_prompt_screenshot = None
                self.error_page_screenshot = None
                browser = p.chromium.launch(headless=True, args=self._chromium_launch_args())
                context_args = {"ignore_https_errors": True}
                if self.browser_storage_state:
                    context_args["storage_state"] = self.browser_storage_state
                context = browser.new_context(**context_args)
                if self.artifacts_dir:
                    context.tracing.start(screenshots=True, snapshots=True, sources=True)
                page = context.new_page()
                page.on("pageerror", lambda error: print(f"    [browser] page error: {error}", flush=True))
                page.on("requestfailed", lambda request: print(
                    f"    [browser] request failed: {request.method} {urlparse(request.url).path}: {request.failure}",
                    flush=True,
                ))
                page.on("request", self._observe_authorization)
                navigation_response = [None]

                def observe_response(response):
                    if response.request.is_navigation_request() and response.frame == page.main_frame:
                        navigation_response[0] = response

                page.on("response", observe_response)

                try:
                    if method == "POST":
                        parsed = urlparse(local_url)
                        post_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        self._submit_post_form(page, post_url, parsed.query)
                        self._assert_page_loaded(page)
                    else:
                        response = page.goto(local_url, wait_until="load", timeout=30_000)
                        self._assert_page_loaded(page, response)

                    self._drive_interactions(page)
                except Exception as error:
                    self._save_browser_failure(page, context, error)
                    raise
                try:
                    page.wait_for_load_state("networkidle", timeout=10_000)
                except PlaywrightTimeoutError:
                    pass

                page.wait_for_timeout(2_000)
                self.last_screenshot = self._screenshot_data_url(page)
                final_response = navigation_response[0]
                self._assert_page_loaded(page, final_response)
                final_url = urlparse(page.url)
                identity_origin = urlparse(self.identity_url)
                if (
                    final_response is not None
                    and 400 <= final_response.status < 500
                    and (final_url.scheme, final_url.netloc) in {
                        (identity_origin.scheme, identity_origin.netloc),
                        ("https", "identity:5150"),
                    }
                ):
                    self.error_page_screenshot = self.last_screenshot
                self.browser_storage_state = context.storage_state()
                browser.close()
                return True
        except Exception as exc:
            self.login_prompt_screenshot = None
            self.error_page_screenshot = None
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
                    self._assert_page_loaded(page)
                else:
                    response = page.goto(local_url, wait_until="load", timeout=30_000)
                    self._assert_page_loaded(page, response)

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

    def screenshot_for_upload(
        self, urls: list[str], method: str = "GET", requirement: dict | None = None
    ) -> str | None:
        # Capture before submitting the actual login form. A callback screenshot
        # or a separately replayed authorization is not evidence of that prompt.
        if requirement is None:
            return self.login_prompt_screenshot
        source = requirement.get("src")
        if source in {"ExpectLoginPage", "ExpectSecondLoginPage"}:
            return self.login_prompt_screenshot
        if source == "ExpectRedirectUriErrorPage":
            return self.error_page_screenshot
        return None
