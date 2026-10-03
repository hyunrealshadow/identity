import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run
from plans import PLANS, get_plan
from scripts.runner import TestResult
DEFAULT_VARIANT = {
    "server_metadata": "discovery",
    "client_registration": "static_client",
}


class PlanVariantTests(unittest.TestCase):
    def test_hosted_plan_uses_unique_alias_without_mutating_defaults(self):
        with patch.dict(os.environ, {"CONFORMANCE_ALIAS": "identity-run-basic"}):
            plan = get_plan("basic", "https://example.trycloudflare.com")
        self.assertEqual(plan["alias"], "identity-run-basic")
        self.assertEqual(PLANS["basic"]["alias"], "identity")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://example.trycloudflare.com/.well-known/openid-configuration",
        )

    def test_config_profile_uses_no_variant_override(self):
        self.assertIsNone(run.plan_variant_for_profile("config"))

    def test_formpost_basic_profile_uses_default_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("formpost-basic"),
            DEFAULT_VARIANT,
        )

    def test_basic_profile_uses_default_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("basic"),
            DEFAULT_VARIANT,
        )

    def test_dynamic_certification_plan_uses_response_type_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("basic", "oidcc-dynamic-certification-test-plan"),
            {"response_type": "code"},
        )

    def test_formpost_implicit_profile_uses_default_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("formpost-implicit"),
            DEFAULT_VARIANT,
        )

    def test_formpost_hybrid_profile_uses_default_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("formpost-hybrid"),
            DEFAULT_VARIANT,
        )

    def test_rp_init_logout_profile_uses_static_client_response_type_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("rp-init-logout"),
            {
                "client_registration": "static_client",
                "response_type": "code",
            },
        )

    def test_session_profile_uses_static_client_response_type_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("session"),
            {
                "client_registration": "static_client",
                "response_type": "code",
            },
        )

    def test_backchannel_profile_uses_static_client_response_type_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("backchannel"),
            {
                "client_registration": "static_client",
                "response_type": "code",
            },
        )

    def test_third_party_init_profile_uses_response_type_variant(self):
        self.assertEqual(
            run.plan_variant_for_profile("third-party-init"),
            {"response_type": "code id_token"},
        )


class ProfileConfigurationTests(unittest.TestCase):
    def test_every_ci_plan_has_a_supported_profile_and_official_plan_name(self):
        self.assertEqual(set(PLANS), set(run.SUPPORTED_PROFILES))
        self.assertEqual(set(PLANS), set(run.PLAN_NAMES))

    def test_new_formpost_profiles_are_supported(self):
        self.assertIn("formpost-implicit", run.SUPPORTED_PROFILES)
        self.assertIn("formpost-hybrid", run.SUPPORTED_PROFILES)

    def test_rp_init_logout_profile_is_supported(self):
        self.assertIn("rp-init-logout", run.SUPPORTED_PROFILES)

    def test_session_profile_is_supported(self):
        self.assertIn("session", run.SUPPORTED_PROFILES)

    def test_backchannel_profile_is_supported(self):
        self.assertIn("backchannel", run.SUPPORTED_PROFILES)

    def test_third_party_init_profile_is_supported(self):
        self.assertIn("third-party-init", run.SUPPORTED_PROFILES)

    def test_default_plan_name_for_new_formpost_profiles(self):
        self.assertEqual(
            run.default_plan_name_for_profile("formpost-implicit"),
            "oidcc-formpost-implicit-certification-test-plan",
        )
        self.assertEqual(
            run.default_plan_name_for_profile("formpost-hybrid"),
            "oidcc-formpost-hybrid-certification-test-plan",
        )

    def test_default_plan_name_for_rp_init_logout_profile(self):
        self.assertEqual(
            run.default_plan_name_for_profile("rp-init-logout"),
            "oidcc-rp-initiated-logout-certification-test-plan",
        )

    def test_default_plan_name_for_session_profile(self):
        self.assertEqual(
            run.default_plan_name_for_profile("session"),
            "oidcc-session-management-certification-test-plan",
        )

    def test_default_plan_name_for_backchannel_profile(self):
        self.assertEqual(
            run.default_plan_name_for_profile("backchannel"),
            "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
        )

    def test_default_plan_name_for_third_party_init_profile(self):
        self.assertEqual(
            run.default_plan_name_for_profile("third-party-init"),
            "oidcc-3rdparty-init-login-certification-test-plan",
        )


class PlanFileTests(unittest.TestCase):
    def test_public_discovery_origin_does_not_change_default_plan(self):
        plan = get_plan("basic", "https://issuer.example.com/")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://issuer.example.com/.well-known/openid-configuration",
        )
        plan["client"]["client_id"] = "changed"
        original = get_plan("basic")
        self.assertEqual(original["server"]["discoveryUrl"], "https://identity:5150/.well-known/openid-configuration")
        self.assertEqual(original["client"]["client_id"], "00000001-0000-0000-0000-000000000001")

    def test_formpost_implicit_plan_exists_with_expected_defaults(self):
        plan = get_plan("formpost-implicit")

        self.assertEqual(plan["alias"], "identity-formpost-implicit")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://identity:5150/.well-known/openid-configuration",
        )
        self.assertEqual(plan["client"]["client_id"], "00000003-0000-0000-0000-000000000001")

    def test_formpost_hybrid_plan_exists_with_expected_defaults(self):
        plan = get_plan("formpost-hybrid")

        self.assertEqual(plan["alias"], "identity-formpost-hybrid")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://identity:5150/.well-known/openid-configuration",
        )
        self.assertEqual(plan["client"]["client_id"], "00000005-0000-0000-0000-000000000001")

    def test_rp_init_logout_plan_exists_with_expected_defaults(self):
        plan = get_plan("rp-init-logout")

        self.assertEqual(plan["alias"], "identity-rp-init-logout")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://identity:5150/.well-known/openid-configuration",
        )
        self.assertEqual(plan["client"]["client_id"], "00000001-0000-0000-0000-000000000001")
        self.assertEqual(
            plan["client"]["client_secret"],
            "conformance-basic-secret-at-least-32-bytes",
        )

    def test_session_plan_exists_with_expected_defaults(self):
        plan = get_plan("session")

        self.assertEqual(plan["alias"], "identity-session")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://identity:5150/.well-known/openid-configuration",
        )
        self.assertEqual(plan["client"]["client_id"], "00000001-0000-0000-0000-000000000001")
        self.assertEqual(
            plan["client"]["client_secret"],
            "conformance-basic-secret-at-least-32-bytes",
        )

    def test_backchannel_plan_exists_with_expected_defaults(self):
        plan = get_plan("backchannel")

        self.assertEqual(plan["alias"], "identity-backchannel")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://identity:5150/.well-known/openid-configuration",
        )
        self.assertEqual(plan["client"]["client_id"], "00000001-0000-0000-0000-000000000001")
        self.assertEqual(
            plan["client"]["client_secret"],
            "conformance-basic-secret-at-least-32-bytes",
        )

    def test_third_party_init_plan_exists_with_expected_defaults(self):
        plan = get_plan("third-party-init")

        self.assertEqual(plan["alias"], "identity-3rdparty-init-login")
        self.assertEqual(
            plan["server"]["discoveryUrl"],
            "https://identity:5150/.well-known/openid-configuration",
        )
        self.assertEqual(plan["client"]["client_id"], "00000001-0000-0000-0000-000000000001")
        self.assertEqual(
            plan["client"]["client_secret"],
            "conformance-basic-secret-at-least-32-bytes",
        )


class ExitStatusTests(unittest.TestCase):
    def run_plan(self, results, module_count):
        client = MagicMock()
        client.create_plan_from_dict.return_value = "plan-1"
        client.get_modules.return_value = [MagicMock() for _ in range(module_count)]
        runner = MagicMock()
        runner.run_all_tests.return_value = results
        with (
            patch.object(sys, "argv", [
                "run.py", "--no-docker", "--exit-on-failure",
                "--identity-url", "https://issuer.example.com",
                "--discovery-origin", "https://issuer.example.com",
            ]),
            patch.object(run, "ConformanceClient", return_value=client),
            patch.object(run, "BrowserAuthHandler"),
            patch.object(run, "TestRunner", return_value=runner),
        ):
            result = run.main()
        self.assertEqual(
            client.create_plan_from_dict.call_args.args[0]["server"]["discoveryUrl"],
            "https://issuer.example.com/.well-known/openid-configuration",
        )
        return result

    def test_empty_plan_fails(self):
        self.assertEqual(self.run_plan([], 0), 1)

    def test_incomplete_plan_fails(self):
        self.assertEqual(self.run_plan([TestResult("one", "FINISHED", "PASSED", "1")], 2), 1)

    def test_unfinished_test_cannot_pass_with_review_result(self):
        self.assertEqual(self.run_plan([TestResult("one", "WAITING", "REVIEW", "1")], 1), 1)

    def test_completed_plan_passes(self):
        self.assertEqual(self.run_plan([TestResult("one", "FINISHED", "PASSED", "1")], 1), 0)


if __name__ == "__main__":
    unittest.main()
