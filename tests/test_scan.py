"""Unit tests for `leftblock scan`: position conversion, input parsing and cleanup."""

import json
import os
import random
import re
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from leftblock import deep, scan

GITLEAKS = shutil.which("gitleaks")
KANBUS = re.compile(r"(^|/)project/(issues|events)/[^/]+\.jsonl?$")


def address(seed="t"):
    rng = random.Random(seed)
    word = lambda n: "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))
    return word(6) + "." + word(7) + "@" + word(9) + ".com"


def gitleaks_column(text, needle):
    """(line, first, last) as gitleaks reports a match: byte columns, later lines one too far right."""
    data = text.encode("utf-8")
    at = data.index(needle.encode("utf-8"))
    line = data.count(b"\n", 0, at) + 1
    first = at - (data.rfind(b"\n", 0, at) + 1) + 1
    last = first + len(needle.encode("utf-8")) - 1
    shift = 1 if line > 1 else 0
    return line, first + shift, last + shift


class LineIndexTests(unittest.TestCase):
    def check(self, text, needle):
        data = text.encode("utf-8")
        line, first, last = gitleaks_column(text, needle)
        span = scan.byte_span(data, line, first, line, last)
        self.assertEqual(data[span[0]:span[1]], needle.encode("utf-8"))
        return span

    def test_first_line_columns_are_exact(self):
        self.assertEqual(self.check("say " + "hello", "hello"), (4, 9))

    def test_later_lines_undo_the_one_column_shift(self):
        self.check("one\ntwo three\nfour", "three")
        self.check("one\n\n\n  x=value", "value")

    def test_multibyte_text_before_the_match_counts_bytes(self):
        text = "héllo 日本 \U0001F600 target"
        self.assertEqual(self.check(text, "target"), (len(text.encode()) - 6, len(text.encode())))
        self.assertNotEqual(text.index("target"), self.check(text, "target")[0])

    def test_multibyte_text_on_a_later_line(self):
        self.check("üñï\nnaïve 日本 target here", "target")

    def test_carriage_returns_are_ordinary_bytes(self):
        self.check("a\r\nb target\r\nc", "target")

    def test_a_match_over_several_lines(self):
        text = "x\n  begin\nmiddle\nend-here tail\n"
        data = text.encode()
        span = scan.byte_span(data, 2, 3 + 1, 4, len("end-here") + 1)
        self.assertEqual(data[span[0]:span[1]], b"begin\nmiddle\nend-here")

    def test_positions_outside_the_text_are_rejected(self):
        data = b"abc\ndef"
        for position in [(0, 1, 1, 2), (1, 0, 1, 2), (3, 1, 3, 1), (1, 1, 1, 9), (2, 5, 2, 9), (1, 3, 1, 2)]:
            self.assertIsNone(scan.byte_span(data, *position), position)

    def test_empty_text_has_no_position(self):
        self.assertIsNone(scan.byte_span(b"", 1, 1, 1, 1))

    def test_line_of_offset(self):
        index = scan.LineIndex(b"ab\ncd\n\nef")
        self.assertEqual([index.line_of(i) for i in (0, 2, 3, 5, 6, 7)], [1, 1, 2, 2, 3, 4])


class CharacterOffsetTests(unittest.TestCase):
    def test_byte_offsets_of_mixed_width_characters(self):
        text = "aé日\U0001F600b"
        self.assertEqual(scan.char_to_byte_offsets(text), [0, 1, 3, 6, 10, 11])
        data = text.encode()
        offsets = scan.char_to_byte_offsets(text)
        self.assertEqual(data[offsets[3]:offsets[4]].decode(), "\U0001F600")

    def test_lone_surrogates_keep_three_bytes(self):
        text = "a\ud800b"
        offsets = scan.char_to_byte_offsets(text)
        self.assertEqual(offsets, [0, 1, 4, 5])
        self.assertEqual(len(scan.encode(text)), 5)

    def test_escaped_bytes_count_one_byte_each(self):
        raw = b"a\xffb"
        text = raw.decode("utf-8", errors="surrogateescape")
        self.assertEqual(scan.char_to_byte_offsets(text, "surrogateescape"), [0, 1, 2, 3])


class RuleKindTests(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(scan.kind_of("leftblock-personal-email"), "personal")
        self.assertEqual(scan.kind_of("leftblock-home-path-posix"), "personal")
        self.assertEqual(scan.kind_of("leftblock-wif-key"), "crypto")
        self.assertEqual(scan.kind_of("leftblock-bip39-mnemonic"), "crypto")
        self.assertEqual(scan.kind_of("leftblock-openai-key"), "secret")
        self.assertEqual(scan.kind_of("private-key"), "secret")
        self.assertEqual(scan.kind_of("privacy-filter-private_email"), "deep")


class ReadRecordTests(unittest.TestCase):
    def test_records_and_blank_lines(self):
        lines = [b'{"id": "a", "text": "x\\ny"}\n', b"\n", b'  \r\n', b'{"id": "b", "text": "", "extra": 1}']
        self.assertEqual(scan.read_records(lines), [("a", "x\ny"), ("b", "")])

    def test_no_input_is_no_records(self):
        self.assertEqual(scan.read_records([]), [])

    def test_a_bad_line_is_named_by_number_and_never_quoted(self):
        secret = address("bad")
        for bad in [
            '{"id": "a", "text": "%s' % secret, "not json " + secret,
            '{"id": 1, "text": "%s"}' % secret, '{"id": "a"}', '["%s"]' % secret,
            '{"id": "a", "text": null}',
        ]:
            with self.assertRaises(scan.ScanError) as caught:
                scan.read_records([b'{"id": "ok", "text": "fine"}\n', bad.encode() + b"\n"])
            message = str(caught.exception)
            self.assertIn("Line 2", message)
            self.assertNotIn(secret, message)
            self.assertNotIn("\n", message)

    def test_invalid_utf8_and_deep_nesting_are_malformed(self):
        for raw in [b'{"id": "a", "text": "\xff"}', b"[" * 100000]:
            with self.assertRaises(scan.ScanError):
                scan.read_records([raw])


class TempDirTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.object(tempfile, "tempdir", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_private_and_removed(self):
        with scan.private_tempdir() as path:
            self.assertEqual(os.path.dirname(path), self.root)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o700)
            open(os.path.join(path, "x"), "w").close()
        self.assertEqual(os.listdir(self.root), [])

    def test_removed_after_an_error_and_an_interrupt(self):
        for exception in (RuntimeError, KeyboardInterrupt):
            with self.assertRaises(exception):
                with scan.private_tempdir() as path:
                    os.mkdir(os.path.join(path, "records"))
                    raise exception()
            self.assertEqual(os.listdir(self.root), [])

    @unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
    def test_records_are_removed_when_gitleaks_is_interrupted(self):
        with mock.patch.object(scan, "run_gitleaks", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                scan.scan_records([("a", "text")])
        self.assertEqual(os.listdir(self.root), [])


class DeepTextTests(unittest.TestCase):
    def detector(self, value, label="secret", score=0.95):
        def detect(text):
            spans, at = [], text.find(value)
            while at != -1:
                spans.append((at, at + len(value), label, score))
                at = text.find(value, at + len(value))
            return spans
        return detect

    def test_spans_map_back_to_the_whole_text(self):
        value = "Zk3q" * 7
        text = "first line\n" + "x" * 5000 + " " + value + " tail\nlast " + value
        found = deep.scan_text(text, self.detector(value), deep.DEFAULT_LABELS, 0.9)
        self.assertEqual([text[a:b] for a, b, _, _ in found], [value, value])

    def test_threshold_labels_and_shapes(self):
        value = "Zk3q" * 7
        text = "a " + value
        self.assertEqual(deep.scan_text(text, self.detector(value, score=0.5), deep.DEFAULT_LABELS, 0.9), [])
        self.assertEqual(deep.scan_text(text, self.detector(value, "private_person"), deep.DEFAULT_LABELS, 0.9), [])
        self.assertEqual(len(deep.scan_text(text, self.detector(value, "private_person"), deep.ALL_LABELS, 0.9)), 1)
        digest = "a1b2c3d4" * 5
        self.assertEqual(deep.scan_text("h " + digest, self.detector(digest), deep.DEFAULT_LABELS, 0.9), [])

    def test_lines_with_placeholder_words_are_still_scanned(self):
        value = "Zk3q" * 7
        text = "example token " + value
        self.assertEqual(len(deep.scan_text(text, self.detector(value), deep.DEFAULT_LABELS, 0.9)), 1)

    def test_blank_text_does_not_consult_the_model(self):
        def boom(text):
            raise AssertionError("consulted")
        self.assertEqual(deep.scan_text(" \n\n", boom, deep.DEFAULT_LABELS, 0.9), [])


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class RecordScanTests(unittest.TestCase):
    def test_findings_slice_to_the_matched_value(self):
        mail = address()
        text = "héllo 日本 %s\nsecond\n  %s tail" % (mail, mail)
        found = scan.scan_records([("clean", "nothing"), ("r1", text)])
        data = text.encode()
        self.assertEqual([f["file"] for f in found], ["r1", "r1"])
        self.assertEqual([data[f["start"]:f["end"]].decode() for f in found], [mail, mail])
        self.assertEqual([f["line"] for f in found], [1, 3])
        self.assertEqual({f["kind"] for f in found}, {"personal"})

    def test_the_record_id_stands_in_for_the_file_in_the_finding_id(self):
        mail = address()
        a, b = scan.scan_records([("one", mail)]), scan.scan_records([("two", mail)])
        self.assertNotEqual(a[0]["finding_id"], b[0]["finding_id"])
        self.assertEqual(a[0]["finding_id"], scan.allowlist.content_id("leftblock-personal-email", "one", mail))

    def test_path_mode_reports_the_path_and_line(self):
        mail = address()
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "sub", ".git"))
            for name in ("a.txt", os.path.join("sub", "b.txt"), os.path.join("sub", ".git", "c.txt")):
                with open(os.path.join(root, name), "w") as handle:
                    handle.write("x\n" + mail + "\n")
            found = scan.scan_paths([root], kanbus_data=KANBUS)
        self.assertEqual([os.path.relpath(f["file"], root) for f in found], ["a.txt", os.path.join("sub", "b.txt")])
        self.assertEqual({(f["line"], f["start"], f["end"]) for f in found}, {(2, 2, 2 + len(mail))})

    def test_a_missing_path_is_an_error(self):
        with self.assertRaises(scan.ScanError):
            scan.scan_paths([os.path.join(tempfile.gettempdir(), "no-such-leftblock-path")])


if __name__ == "__main__":
    unittest.main()
