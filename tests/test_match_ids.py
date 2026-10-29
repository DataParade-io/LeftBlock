"""Base58check validation and match-based override ids, with synthetic data only."""

import hashlib
import random
import sys
import unittest
from pathlib import Path

from leftblock import allow, validators
from leftblock.core import CheckerResult

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_sensitive_rules import rand_wif
from test_commit_gate import RepositoryFixture


def b58check(payload):
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, out = int.from_bytes(raw, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        out = validators.BASE58[rest] + out
    return out


class Base58CheckTests(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(7)
        self.key = bytes(self.rng.randrange(256) for _ in range(32))

    def test_valid_wif_layouts(self):
        for version in (0x80, 0xEF):
            self.assertTrue(validators.valid_wif(b58check(bytes([version]) + self.key)))
            self.assertTrue(validators.valid_wif(b58check(bytes([version]) + self.key + b"\x01")))

    def test_wrong_version_length_or_flag_is_invalid(self):
        self.assertFalse(validators.valid_wif(b58check(b"\x05" + self.key + b"\x01")))
        self.assertFalse(validators.valid_wif(b58check(b"\x80" + self.key[:30] + b"\x01")))
        self.assertFalse(validators.valid_wif(b58check(b"\x80" + self.key + b"\x02")))
        self.assertFalse(validators.valid_wif(b58check(b"\x80" + self.key + b"\x01\x01")))

    def test_bad_checksum_and_bad_alphabet_are_invalid(self):
        good = rand_wif(self.rng)
        self.assertTrue(validators.valid_wif(good))
        self.assertFalse(validators.valid_wif(good[:-1] + ("2" if good[-1] != "2" else "3")))
        self.assertFalse(validators.valid_wif(good[:-1] + "0"))
        self.assertFalse(validators.valid_wif(""))
        self.assertIsNone(validators.base58check_decode("1"))

    def test_random_runs_almost_never_pass(self):
        rng = random.Random(1)
        runs = ("".join(rng.choice(validators.BASE58) for _ in range(52)) for _ in range(500))
        self.assertFalse(any(validators.valid_wif(r) for r in runs))


class IdTests(RepositoryFixture):
    FILE = "a.txt"

    def stage(self, text):
        (self.repo / self.FILE).write_text(text)
        self.git("add", self.FILE, check=True)

    def finding(self, start_col, end_col, line=1):
        return {"File": self.FILE, "RuleID": "r", "StartLine": line, "EndLine": line,
                "StartColumn": start_col, "EndColumn": end_col}

    def ids(self, finding):
        result = CheckerResult("c", False, [finding])
        allow.attach_ids(str(self.repo), [result])
        return finding

    def test_id_follows_the_match_not_the_line(self):
        self.stage("one VALUE1234 two\n")
        before = self.ids(self.finding(5, 13))
        self.stage("completely different VALUE1234 text\n")
        after = self.ids(self.finding(22, 30))
        self.assertEqual(before["id"], after["id"])
        self.assertEqual(before["id"], allow.content_id("r", self.FILE, "VALUE1234"))
        self.assertNotEqual(before["legacy_id"], after["legacy_id"])
        self.stage("one OTHER12345 two\n")
        self.assertNotEqual(before["id"], self.ids(self.finding(5, 13))["id"])

    def test_later_lines_of_a_hunk_are_one_column_further_right(self):
        # Gitleaks reports line 2 of a hunk one column too far right; line 1 is exact.
        self.stage("one VALUE1234 two\nxx VALUE1234 yy\n")
        first = self.ids(self.finding(5, 13))
        second = self.ids(self.finding(5, 13, line=2))  # exact columns would be 4..12
        self.assertEqual(first["id"], second["id"])

    def test_columns_are_bytes_not_characters(self):
        self.stage("é VALUE1234\n")
        found = self.ids(self.finding(4, 12))
        self.assertEqual(found["id"], allow.content_id("r", self.FILE, "VALUE1234"))

    def test_legacy_line_id_is_still_accepted(self):
        line = "one VALUE1234 two"
        self.stage(line + "\n")
        found = self.ids(self.finding(5, 13))
        self.assertEqual(found["legacy_id"], allow.content_id("r", self.FILE, line))
        for ident in (found["id"], found["legacy_id"]):
            result = CheckerResult("c", False, [dict(found)])
            entries = [{"id": ident, "rule": "r", "file": self.FILE, "reason": "reviewed and fine"}]
            applied = allow.apply_allowlist([result], entries)
            self.assertEqual(len(applied), 1)
            self.assertTrue(result.clean)
            self.assertEqual(applied[0][0]["id"], ident)

    def test_unreadable_columns_fall_back_to_the_line_id(self):
        self.stage("one VALUE1234 two\n")
        found = self.ids({"File": self.FILE, "RuleID": "r", "StartLine": 1, "EndLine": 1})
        self.assertEqual(found["id"], found["legacy_id"])


if __name__ == "__main__":
    unittest.main()
