import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.browser_auth import BrowserAuthHandler


class BrowserAuthHandlerTests(unittest.TestCase):
    def test_complete_browser_login_navigates_to_conformance_auto_login_page(self):
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

        self.assertIn('action="https://localhost:5150/oauth2/authorize"', page.content)
        self.assertIn('name="response_type" value="code"', page.content)
        self.assertIn('name="client_id" value="client-123"', page.content)
        self.assertEqual(page.wait_calls, [("load", 30000)])


class FakePage:
    def __init__(self):
        self.content = None
        self.goto_calls = []
        self.wait_calls = []

    def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append((url, wait_until, timeout))

    def set_content(self, content, wait_until=None):
        self.content = content

    def wait_for_load_state(self, state, timeout=None):
        self.wait_calls.append((state, timeout))


if __name__ == "__main__":
    unittest.main()
