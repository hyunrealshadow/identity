import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.browser_auth import BrowserAuthHandler


class BrowserAuthHandlerTests(unittest.TestCase):
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
            "--host-resolver-rules=MAP identity 127.0.0.1,MAP login 127.0.0.1,MAP host.docker.internal 127.0.0.1",
            handler._chromium_launch_args(),
        )

    def test_localize_url_keeps_docker_identity_origin_for_browser_cookie_scope(self):
        handler = BrowserAuthHandler("https://localhost:5150")

        self.assertEqual(
            handler._localize_url("https://identity:5150/oauth2/authorize"),
            "https://identity:5150/oauth2/authorize",
        )

    def test_complete_browser_login_uses_explicit_op_origin(self):
        handler = BrowserAuthHandler("https://localhost:5150")
        page = FakePage("http://login:3000/login?login_id=login-123")

        self.assertTrue(
            handler._complete_browser_login(
                page, "login-123", "https://identity:5150"
            )
        )
        self.assertEqual(
            page.goto_calls,
            [
                (
                    "https://identity:5150/conformance/auto-login?login_id=login-123",
                    "load",
                    30000,
                ),
            ],
        )

    def test_complete_browser_login_defaults_to_configured_identity_origin(self):
        handler = BrowserAuthHandler("https://localhost:5150")
        page = FakePage()

        self.assertTrue(handler._complete_browser_login(page, "login-123"))
        self.assertEqual(
            page.goto_calls,
            [
                (
                    "https://localhost:5150/conformance/auto-login?login_id=login-123",
                    "load",
                    30000,
                )
            ],
        )
        self.assertEqual(page.wait_calls, [("load", 30000)])

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


class FakeResponse:
    def __init__(self, status):
        self.status = status


if __name__ == "__main__":
    unittest.main()
