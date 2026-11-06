import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leftblock import scan_report
from leftblock.cli import KANBUS_DATA
from test_scan import address


@unittest.skipUnless(shutil.which("gitleaks"), "requires gitleaks")
class ScanReportTests(unittest.TestCase):
    def setUp(self):
        self.value = address("scan-report")

    def run_cli(self, *args, data=None, env=None):
        result = subprocess.run(
            [sys.executable, "-m", "leftblock.cli", "scan", "--format", "report", *args],
            input=data, text=True, capture_output=True, env=env,
        )
        self.assertNotIn(self.value, result.stdout + result.stderr)
        return result, json.loads(result.stdout)

    def test_file_findings_with_model_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "source.txt")
            source.write_text("first line\n" + self.value, encoding="utf-8")
            result, report = self.run_cli("--privacy-filter", "off", str(source))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["privacyFilter"], {"status": "disabled"})
        self.assertEqual(report["rules"]["findingCount"], 1)
        self.assertEqual(report["findings"][0]["line"], 2)
        self.assertEqual(report["findings"][0]["file"], str(source))

    def test_model_load_failure_retains_record_findings(self):
        env = {**os.environ, "LEFTBLOCK_DEEP_DETECTOR": "no_such_detector:create"}
        record = json.dumps({"id": "part-1", "text": self.value})
        result, report = self.run_cli("--jsonl", data=record, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["privacyFilter"]["status"], "unavailable")
        self.assertEqual(report["rules"]["findingCount"], 1)
        self.assertEqual(report["findings"][0]["id"], "part-1")
        self.assertIn("LeftBlock rules completed (1 findings)", result.stderr)
        result, report = self.run_cli("--jsonl", data='{"id":"clean","text":"hello"}', env=env)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["privacyFilter"]["status"], "unavailable")

    def test_model_timeout_retains_rule_findings(self):
        original = subprocess.run

        def timeout_model(args, **kwargs):
            if args[0] == sys.executable:
                self.assertEqual(kwargs["env"]["HF_HUB_OFFLINE"], "1")
                raise subprocess.TimeoutExpired(args, 1)
            return original(args, **kwargs)

        with mock.patch.object(subprocess, "run", side_effect=timeout_model):
            report = scan_report.run([], [("part-1", self.value)], "auto", KANBUS_DATA)
        self.assertEqual(report["privacyFilter"]["reason"], "timeout")
        self.assertEqual(report["rules"]["findingCount"], 1)
        self.assertEqual(len(report["findings"]), 1)

    def test_invalid_path_reports_rule_error_and_no_model_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, report = self.run_cli(str(Path(tmp, "missing.txt")))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["rules"]["status"], "error")
        self.assertEqual(report["privacyFilter"], {"status": "not-run"})
