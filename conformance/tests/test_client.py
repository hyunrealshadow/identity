import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.client import ConformanceClient


class ConformanceClientPlanTests(unittest.TestCase):
    def test_create_plan_omits_variant_query_when_explicitly_none(self):
        client = ConformanceClient("https://suite.example.com")
        client.session.post = MagicMock()
        client.session.post.return_value.raise_for_status = MagicMock()
        client.session.post.return_value.json.return_value = {"id": "plan-1"}

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as fh:
            json.dump({"alias": "identity-config"}, fh)
            path = fh.name

        try:
            plan_id = client.create_plan(path, plan_name="oidcc-config-certification-test-plan", variant=None)
        finally:
            os.unlink(path)

        self.assertEqual(plan_id, "plan-1")
        self.assertEqual(
            client.session.post.call_args.args[0],
            "https://suite.example.com/api/plan?planName=oidcc-config-certification-test-plan",
        )


if __name__ == "__main__":
    unittest.main()
