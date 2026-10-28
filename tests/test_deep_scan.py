"""Unit tests for the deep scan's filters and plumbing (no model involved)."""

import hashlib
import os
import re
import unittest

from leftblock import allow, deep

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

KANBUS = re.compile(r"(^|/)project/(issues|events)/[^/]+\.jsonl?$")
RULESET = os.path.join(os.path.dirname(deep.__file__), "data", "gitleaks.toml")


AT = "@"


def hexa(n, seed="a1b2c3d4e5f60718"):
    return (seed * n)[:n]


class SecretShapeTests(unittest.TestCase):
    def test_identifier_shapes_are_not_secrets(self):
        uuid = "-".join([hexa(8), hexa(4), hexa(4), hexa(4), hexa(12)])
        for value in [
            uuid, hexa(7), hexa(40), hexa(64), "#" + hexa(6), "#" + hexa(3), "#" + hexa(8),
            "2026-10-28", "2026-10-28T09:15:00Z", "2026-10-28 09:15:00.123+02:00",
            "PPY-" + hexa(6), "ISS-123", "kanbus-" + hexa(6),
            '"' + hexa(40) + '"',
        ]:
            self.assertTrue(deep.secret_shaped(value), value)

    def test_other_values_are_secrets(self):
        for value in ["Zk3" + "9qLw" * 6, "p4ss" + "w0rd" * 3, hexa(6) + "g", "token-" + "Zq" * 8]:
            self.assertFalse(deep.secret_shaped(value), value)


class EmailAllowTests(unittest.TestCase):
    def test_allowed_addresses(self):
        for value in [
            "someone" + AT + "example.org", "a" + AT + "b.test", "a" + AT + "b.example",
            "a" + AT + "b.invalid", "a" + AT + "b.localhost", "a" + AT + "example.edu", "noreply" + AT + "vendor.co",
            "no-reply" + AT + "vendor.co", "1234+x" + AT + "users.noreply.github.com", "git" + AT + "github.com",
            "ops" + AT + "build.internal", "ops" + AT + "internal", "<ops" + AT + "build.internal>",
        ]:
            self.assertTrue(deep.email_allowed(value), value)

    def test_personal_addresses_are_not_allowed(self):
        for value in ["someone" + AT + "vendor.co", "a" + AT + "test.com", "a" + AT + "example.test.co", "a" + AT + "internal.co"]:
            self.assertFalse(deep.email_allowed(value), value)

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11")
    def test_shipped_ruleset_allowlist_is_covered(self):
        with open(RULESET, "rb") as handle:
            rules = tomllib.load(handle)["rules"]
        shipped = next(r for r in rules if r["id"] == "leftblock-personal-email")
        ours = {p.pattern for p in deep.EMAIL_ALLOW}
        self.assertTrue(shipped["allowlist"]["regexes"])
        for regex in shipped["allowlist"]["regexes"]:
            self.assertIn(regex, ours)


class SkipTests(unittest.TestCase):
    def test_skipped_paths(self):
        for path in [
            "project/issues/a.json", "project/events/a.jsonl", "x/project/issues/a.json",
            "project/.cache/index.json", "package-lock.json", "a/yarn.lock", "poetry.lock",
            "go.sum", "pnpm-lock.yaml", "a/app.min.js", "a/app.min.css", "a/b.js.map",
            "node_modules/x/y.js", "vendor/x.go", "a/b_pb2.py", "a/b.generated.ts",
            "__pycache__/x.pyc", ".leftblock-allow.yml", "sub/.leftblock-allow.yml",
        ]:
            self.assertTrue(deep.skip_file(path, KANBUS), path)

    def test_scanned_paths(self):
        for path in ["src/app.py", "project/notes.json", "README.md", "lockdown.py", "docs/vendors.md"]:
            self.assertFalse(deep.skip_file(path, KANBUS), path)

    def test_skip_line_words(self):
        for line in ["Placeholder", "an EXAMPLE", "fake_token", "synthetic data", "dummy"]:
            self.assertTrue(deep.SKIP_LINE.search(line), line)
        self.assertFalse(deep.SKIP_LINE.search("service_token = 1"))


class OptionTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(deep.parse_labels(""), deep.DEFAULT_LABELS)
        self.assertEqual(deep.parse_labels("private_person, secret"), deep.DEFAULT_LABELS + ("private_person",))
        with self.assertRaises(ValueError):
            deep.parse_labels("nope")

    def test_threshold(self):
        self.assertEqual(deep.parse_threshold("0.5"), 0.5)
        for bad in ["x", "1.5", "-1"]:
            with self.assertRaises(ValueError):
                deep.parse_threshold(bad)


class ScanTests(unittest.TestCase):
    @staticmethod
    def scan(additions, spans_for, labels=deep.DEFAULT_LABELS, threshold=0.9):
        return deep.scan(
            [(p, n, t.encode()) for p, n, t in additions], spans_for, labels, threshold, KANBUS,
        )

    def test_span_is_attributed_to_its_line_and_value_is_not_kept(self):
        secret = "Zk39qLwT" * 3

        def detector(text):
            at = text.find(secret)
            return [(at, at + len(secret), "secret", 0.95)] if at >= 0 else []

        found = self.scan([("a.py", 10, "x = 1"), ("a.py", 42, "t = %r" % secret)], detector)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["File"], found[0]["line"]), ("a.py", 42))
        self.assertEqual(found[0]["RuleID"], "privacy-filter-secret")
        self.assertNotIn(secret, repr(found))

    def test_id_matches_the_allow_file_hash(self):
        line = "t = value"
        found = self.scan([("a.py", 3, line)], lambda text: [(0, 1, "secret", 0.99)])
        digest = hashlib.sha256(("privacy-filter-secret\0a.py\0" + line).encode()).hexdigest()[:16]
        self.assertEqual(found[0]["id"], digest)
        self.assertEqual(found[0]["id"], allow.content_id("privacy-filter-secret", "a.py", line))

    def test_threshold_labels_and_filters(self):
        add = [("a.py", 1, "value")]
        span = lambda label, score, v="value": (lambda text: [(0, len(v), label, score)])
        self.assertEqual(len(self.scan(add, span("secret", 0.9))), 1)
        self.assertEqual(self.scan(add, span("secret", 0.89)), [])
        self.assertEqual(self.scan(add, span("private_person", 0.99)), [])
        self.assertEqual(len(self.scan(add, span("private_person", 0.99), labels=deep.ALL_LABELS)), 1)
        self.assertEqual(self.scan([("a.py", 1, hexa(40))], span("secret", 0.99, hexa(40))), [])
        self.assertEqual(self.scan([("a.py", 1, "ops" + AT + "vendor.internal")], span("private_email", 0.99, "ops" + AT + "vendor.internal")), [])

    def test_skipped_files_and_lines_never_reach_the_detector(self):
        calls = []

        def detector(text):
            calls.append(text)
            return []

        self.scan([("package-lock.json", 1, "x"), ("a.py", 1, "placeholder"), ("a.py", 2, "   ")], detector)
        self.assertEqual(calls, [])

    def test_long_input_is_chunked_and_line_numbers_survive(self):
        lines = [("a.py", n, "line %d " % n + "x" * 500) for n in range(1, 30)]
        sizes = []

        def detector(text):
            sizes.append(len(text))
            at = text.find("line 25 ")
            return [(at, at + 4, "secret", 0.99)] if at >= 0 else []

        found = self.scan(lines, detector)
        self.assertGreater(len(sizes), 1)
        self.assertTrue(all(size <= deep.CHUNK_CHARS for size in sizes))
        self.assertEqual([f["line"] for f in found], [25])

    def test_pipeline_labels_are_normalised(self):
        self.assertEqual(deep._normalise("B-private_email"), "private_email")
        self.assertEqual(deep._normalise("SECRET"), "secret")


if __name__ == "__main__":
    unittest.main()
