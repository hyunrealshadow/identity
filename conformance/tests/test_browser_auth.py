import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.browser_auth import BrowserAuthHandler


class BrowserAuthHandlerTests(unittest.TestCase):
    def test_unregistered_post_logout_redirect_requires_the_actual_op_error(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler.last_screenshot = "logout-callback"
        handler.login_prompt_screenshot = "login-form"
        for source in ("ExpectPostLogoutRedirectUriNotRegisteredErrorPage", "ExpectInvalidIdTokenHintErrorPage", "ExpectIdTokenHintRequiredErrorPage"):
            requirement = {"src": source}
            self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))
            handler.error_page_screenshot = "op-logout-error"
            self.assertEqual(handler.screenshot_for_upload([], requirement=requirement), "op-logout-error")
            handler.reset_session()
            self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))

    def test_successful_logout_evidence_cannot_use_a_login_error_or_callback(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler.last_screenshot = "rp-callback"
        handler.login_prompt_screenshot = "password-prompt"
        handler.error_page_screenshot = "op-error"
        requirement = {"src": "ExpectSuccessfulLogoutPage"}
        self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))
        handler.logout_page_screenshot = "op-successful-logout"
        self.assertEqual(handler.screenshot_for_upload([], requirement=requirement), "op-successful-logout")
        handler.reset_session()
        self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))

    def test_missing_nonce_requirement_uses_only_the_observed_op_error_page(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        requirement = {"src": "ExpectRequestMissingNonceErrorPage"}
        handler.login_prompt_screenshot = "login-prompt"
        handler.last_screenshot = "callback"
        self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))
        handler.error_page_screenshot = "observed-nonce-error"
        self.assertEqual(handler.screenshot_for_upload([], requirement=requirement), "observed-nonce-error")
        handler.reset_session()
        self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))

    def test_failure_diagnostics_are_saved_without_becoming_review_evidence(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        page = MagicMock()
        page.url = "https://login.example.com/login"
        page.locator.return_value.inner_text.return_value = "Unable to continue"
        context = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            handler.artifacts_dir = directory
            handler._save_browser_failure(page, context, RuntimeError("navigation timed out"))
            failure = next(Path(directory).iterdir())
            self.assertEqual(json.loads((failure / "failure.json").read_text())["url"], page.url)
            self.assertEqual((failure / "page.txt").read_text(), "Unable to continue")
            context.tracing.stop.assert_called_once_with(path=str(failure / "trace.zip"))
            page.screenshot.assert_called_once()
        self.assertIsNone(handler.screenshot_for_upload([], requirement={"src": "ExpectLoginPage"}))

    def test_assert_page_loaded_accepts_protocol_error_page(self):
        page = FakePage(content="<h1>授权请求无效</h1>")

        BrowserAuthHandler._assert_page_loaded(page, FakeResponse(400))

    def test_assert_page_loaded_rejects_vite_block_page(self):
        page = FakePage(content='Blocked request. This host ("login") is not allowed.')

        with self.assertRaisesRegex(RuntimeError, "Vite rejected browser host"):
            BrowserAuthHandler._assert_page_loaded(page)

    def test_browser_launch_args_resolve_docker_identity_on_host(self):
        handler = BrowserAuthHandler("https://localhost:5150")

        self.assertIn(
            "--host-resolver-rules=MAP identity 127.0.0.1,MAP host.docker.internal 127.0.0.1",
            handler._chromium_launch_args(),
        )

    def test_localize_url_keeps_docker_identity_origin_for_browser_cookie_scope(self):
        handler = BrowserAuthHandler("https://localhost:5150")

        self.assertEqual(
            handler._localize_url("https://identity:5150/oauth2/authorize"),
            "https://identity:5150/oauth2/authorize",
        )

    def test_callback_screenshots_are_not_uploaded_as_login_ui_evidence(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler.last_screenshot = "data:image/png;base64,diagnostic"
        self.assertIsNone(handler.screenshot_for_upload(["https://suite.example.com/callback"]))

    def test_only_observed_login_prompt_is_uploaded_and_reset_between_modules(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler.login_prompt_screenshot = "data:image/png;base64,login-prompt"
        self.assertEqual(handler.screenshot_for_upload([]), handler.login_prompt_screenshot)
        handler.reset_session()
        self.assertIsNone(handler.screenshot_for_upload([]))

    def test_login_hint_selects_the_second_seeded_account(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler._observe_authorization(FakeRequest("https://issuer.example.com/oauth2/authorize?login_hint=conformance-test-2@example.com"))
        self.assertEqual(handler.account_index, 1)

    def test_error_evidence_cannot_be_substituted_with_a_login_prompt(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler.login_prompt_screenshot = "login-prompt"
        requirement = {"src": "ExpectRedirectUriErrorPage"}
        self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))
        handler.error_page_screenshot = "actual-op-error"
        self.assertEqual(handler.screenshot_for_upload([], requirement=requirement), "actual-op-error")
        self.assertEqual(handler.screenshot_for_upload([], requirement={"src": "ExpectSecondLoginPage"}), "login-prompt")
        self.assertIsNone(handler.screenshot_for_upload([], requirement={"src": "UnknownEvidence"}))
        handler.reset_session()
        self.assertIsNone(handler.screenshot_for_upload([], requirement=requirement))

    def test_account_selection_uses_the_other_account_without_discarding_sessions(self):
        handler = BrowserAuthHandler("https://issuer.example.com")
        handler.browser_storage_state = {"cookies": [{"name": "sessions"}]}
        handler._observe_authorization(FakeRequest("https://issuer.example.com/oauth2/authorize?prompt=select_account"))
        self.assertEqual(handler.account_index, 1)
        self.assertIsNotNone(handler.browser_storage_state)

    def test_foreign_origin_cannot_supply_credentials_or_change_account(self):
        handler = BrowserAuthHandler("https://issuer.example.com", "https://login.example.com")
        handler._observe_authorization(FakeRequest("https://foreign.example.com/oauth2/authorize?prompt=select_account"))
        self.assertEqual(handler.account_index, 0)
        handler._drive_interactions(FakePage(url="https://foreign.example.com/login"))

    def test_submit_post_form_builds_browser_post_for_non_conformance_urls(self):
        handler = BrowserAuthHandler("https://localhost:5150")
        page = FakePage()

        handler._submit_post_form(
            page,
            "https://localhost:5150/oauth2/authorize",
            "response_type=code&client_id=client-123",
        )

        self.assertIn('action="https://localhost:5150/oauth2/authorize"', page.content())
        self.assertIn('name="response_type" value="code"', page.content())
        self.assertIn('name="client_id" value="client-123"', page.content())
        self.assertEqual(page.wait_calls, [("load", 30000)])


class FakePage:
    def __init__(self, url="", content=""):
        self.url = url
        self._content = content
        self.goto_calls = []
        self.wait_calls = []

    def goto(self, url, wait_until=None, timeout=None):
        self.url = url
        self.goto_calls.append((url, wait_until, timeout))

    def set_content(self, content, wait_until=None):
        self._content = content

    def content(self):
        return self._content

    def wait_for_load_state(self, state, timeout=None):
        self.wait_calls.append((state, timeout))


class FakeRequest:
    def __init__(self, url):
        self.url = url


class FakeResponse:
    def __init__(self, status):
        self.status = status


if __name__ == "__main__":
    unittest.main()
