import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.client import ConformanceClient


class ConformanceClientPlanTests(unittest.TestCase):
    def setUp(self):
        self.client = ConformanceClient("https://suite.example.com")
        self.client.session.post = MagicMock()
        self.client.session.post.return_value.raise_for_status = MagicMock()
        self.client.session.post.return_value.json.return_value = {"id": "plan-1"}

    def test_create_plan_omits_variant_query_when_explicitly_none(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as fh:
            json.dump({"alias": "identity-config"}, fh)
            path = fh.name

        try:
            plan_id = self.client.create_plan(path, plan_name="oidcc-config-certification-test-plan", variant=None)
        finally:
            os.unlink(path)

        self.assertEqual(plan_id, "plan-1")
        self.assertEqual(
            self.client.session.post.call_args.args[0],
            "https://suite.example.com/api/plan?planName=oidcc-config-certification-test-plan",
        )

    def test_create_plan_from_dict_omits_variant_query_when_explicitly_none(self):
        config = {"alias": "identity-config"}
        plan_id = self.client.create_plan_from_dict(config, plan_name="oidcc-config-certification-test-plan", variant=None)

        self.assertEqual(plan_id, "plan-1")
        self.assertEqual(
            self.client.session.post.call_args.args[0],
            "https://suite.example.com/api/plan?planName=oidcc-config-certification-test-plan",
        )

    def test_create_plan_from_dict_uses_default_variant_when_not_specified(self):
        config = {"alias": "identity"}
        plan_id = self.client.create_plan_from_dict(config, plan_name="oidcc-basic-certification-test-plan")

        self.assertEqual(plan_id, "plan-1")
        url = self.client.session.post.call_args.args[0]
        self.assertIn("variant=", url)

    def test_create_plan_from_dict_includes_variant_when_provided(self):
        config = {"alias": "identity"}
        variant = {"response_type": "code"}
        plan_id = self.client.create_plan_from_dict(config, plan_name="oidcc-test-plan", variant=variant)

        self.assertEqual(plan_id, "plan-1")
        url = self.client.session.post.call_args.args[0]
        self.assertIn("variant=", url)


if __name__ == "__main__":
    unittest.main()
