import json
import unittest

from leftblock import ci


IDENTITY = {"sha": "a" * 40, "tree": "b" * 40, "describe": "v1-2-gaaaaaaa"}
TOOLS = {"node": "v20.0.0", "python3": "Python 3.12.0", "git": "git version 2.45.0", "leftblock": "0.9.0"}
FINISHED_AT = "2026-10-31T12:00:00Z"


class BuildReceiptTests(unittest.TestCase):
    def build(self, exit_code, secret=None):
        return ci.build_receipt(IDENTITY, "npm test", exit_code, 12.3456, "2026-10-31T11:59:48Z", FINISHED_AT, TOOLS, secret)

    def test_zero_exit_is_success_and_nonzero_is_failure(self):
        self.assertEqual(self.build(0)["result"], "success")
        self.assertEqual(self.build(2)["result"], "failure")

    def test_unsigned_receipt_has_no_signature(self):
        self.assertNotIn("signature", self.build(0))

    def test_signature_covers_sha_tree_result_and_finish_time(self):
        from leftblock.core import compute_hmac
        receipt = self.build(0, "s3cret")
        expected = compute_hmac(IDENTITY["sha"], IDENTITY["tree"], "success", FINISHED_AT, "s3cret")
        self.assertEqual(receipt["signature"], "hmac-sha256:" + expected)

    def test_signature_changes_with_the_result(self):
        self.assertNotEqual(self.build(0, "s3cret")["signature"], self.build(1, "s3cret")["signature"])

    def test_receipt_serializes_with_the_documented_fields(self):
        receipt = json.loads(json.dumps(self.build(0, "s3cret")))
        for field in ("sha", "tree", "checks", "result", "started_at", "finished_at", "tools", "leftblock_version", "host", "signature"):
            self.assertIn(field, receipt)
        self.assertEqual(receipt["checks"], [{"command": "npm test", "exit_code": 0, "duration_s": 12.346}])


class DescribeStatusTests(unittest.TestCase):
    def test_unsigned_description(self):
        receipt = ci.build_receipt(IDENTITY, "npm test", 0, 41.6, "x", FINISHED_AT, TOOLS, None)
        self.assertEqual(ci.describe_status(receipt), "success 1 checks 42s")

    def test_signed_description_ends_with_twelve_hex_digits(self):
        receipt = ci.build_receipt(IDENTITY, "npm test", 1, 3, "x", FINISHED_AT, TOOLS, "s3cret")
        description = ci.describe_status(receipt)
        self.assertTrue(description.startswith("failure 1 checks 3s sig:"))
        self.assertEqual(len(description.rsplit("sig:", 1)[1]), 12)


class ReadSettingsTests(unittest.TestCase):
    def read(self, config):
        import tempfile, os, yaml
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".leftblock.yml"), "w") as handle:
                yaml.safe_dump(config, handle)
            return ci.read_ci_settings(root)

    def test_defaults(self):
        settings = self.read({"ci": {"command": "npm test"}})
        self.assertEqual(settings, {"command": "npm test", "status_context": "leftblock/ci", "sign": False})

    def test_missing_or_blank_command_is_refused(self):
        for config in ({}, {"ci": {}}, {"ci": {"command": "  "}}, {"ci": {"command": 5}}):
            with self.subTest(config=config), self.assertRaises(ci.CiRefusal):
                self.read(config)

    def test_non_boolean_sign_is_refused(self):
        with self.assertRaises(ci.CiRefusal):
            self.read({"ci": {"command": "true", "sign": "yes please"}})


if __name__ == "__main__":
    unittest.main()
