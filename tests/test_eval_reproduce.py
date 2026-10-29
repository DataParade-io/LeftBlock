"""Unit tests for the evaluation's reproducibility helpers: pins, provenance, resume, compare, workflow."""

import os
import re
import tempfile
import unittest

import yaml

from eval import compare, creddata, detectors, pins, prereq, provenance, scoring

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def unit(file, start, truth="F", category="Salt"):
    return scoring.make_unit(file, start, start, truth, [category])


class PinTests(unittest.TestCase):
    def test_gitleaks_pin_matches_the_workflows(self):
        for name in ("ci.yml", "eval.yml"):
            with open(os.path.join(ROOT, ".github", "workflows", name), encoding="utf-8") as handle:
                self.assertIn("GITLEAKS_VERSION=" + pins.GITLEAKS_VERSION, handle.read(), name)

    def test_requirements_are_exact_pins(self):
        found = pins.requirements()
        for name in ("torch", "transformers", "pybase62"):
            self.assertIn(name, found)
        with open(pins.REQUIREMENTS, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith(("#", "-")):
                    self.assertRegex(line, r"^[A-Za-z0-9_.\-]+==[0-9][^\s]*$")

    def test_model_revision_is_a_commit_hash(self):
        self.assertRegex(pins.MODEL_REVISION, r"^[0-9a-f]{40}$")
        self.assertRegex(pins.CREDDATA_COMMIT, r"^[0-9a-f]{40}$")

    def test_eval_workflow_runs_only_on_manual_dispatch(self):
        with open(os.path.join(ROOT, ".github", "workflows", "eval.yml"), encoding="utf-8") as handle:
            triggers = yaml.safe_load(handle)
        triggers = triggers.get("on", triggers.get(True))
        self.assertEqual(list(triggers), ["workflow_dispatch"])


class VersionTests(unittest.TestCase):
    def test_versions_are_normalised(self):
        self.assertEqual(detectors.normalise_version("v8.30.1\n"), "8.30.1")
        self.assertEqual(detectors.normalise_version("8.30.1"), "8.30.1")
        self.assertEqual(detectors.normalise_version(""), "")

    def test_install_hint_names_the_pinned_release(self):
        hint = prereq.gitleaks_install_hint()
        self.assertIn("v" + pins.GITLEAKS_VERSION, hint)


class DigestTests(unittest.TestCase):
    def write(self, root, files):
        for relative, content in files:
            path = os.path.join(root, *relative.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(content)

    def test_tree_digest_ignores_creation_order_and_tracks_content(self):
        files = [("a/x.txt", b"1"), ("b.txt", b"2"), ("a/y.txt", b"3")]
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            self.write(one, files)
            self.write(two, list(reversed(files)))
            self.assertEqual(provenance.tree_sha256(one), provenance.tree_sha256(two))
            self.write(two, [("b.txt", b"changed")])
            self.assertNotEqual(provenance.tree_sha256(one)[0], provenance.tree_sha256(two)[0])

    def test_sample_digest_ignores_order(self):
        sample = [unit("f", n)._replace(weight=2.0) for n in range(5)]
        self.assertEqual(provenance.sample_sha256(sample), provenance.sample_sha256(list(reversed(sample))))

    def test_tier_digest_is_stable_text(self):
        self.assertRegex(provenance.tiers_sha256(), r"^[0-9a-f]{64}$")


class SamplingTests(unittest.TestCase):
    def units(self):
        return [unit("f%02d" % n, 1) for n in range(40)]

    def keys(self, sample):
        return [(u.file, u.weight) for u in sample]

    def test_same_seed_same_sample_whatever_the_input_order(self):
        units = self.units()
        first = creddata.select_sample(units, 10, 7)
        second = creddata.select_sample(list(reversed(units)), 10, 7)
        self.assertEqual(self.keys(first), self.keys(second))

    def test_other_seed_other_sample(self):
        units = self.units()
        self.assertNotEqual(self.keys(creddata.select_sample(units, 10, 7)), self.keys(creddata.select_sample(units, 10, 8)))

    def test_smoke_subset_takes_whole_files_and_is_seeded(self):
        sample = creddata.select_sample(self.units(), 40, 7)
        small = creddata.smoke_subset(sample, 5, 7)
        self.assertEqual(len({u.file for u in small}), 5)
        self.assertEqual(self.keys(small), self.keys(creddata.smoke_subset(sample, 5, 7)))


class ResumeTests(unittest.TestCase):
    def test_a_cache_cut_short_by_an_interruption_is_read_and_appended_to(self):
        os.environ["LEFTBLOCK_DEEP_DETECTOR"] = "stub_detector:factory"
        os.environ.pop("LEFTBLOCK_STUB_SPANS", None)
        import sys
        sys.path.insert(0, os.path.join(ROOT, "features"))
        try:
            additions = [("a.py", 1, b"x = 1"), ("b.py", 1, b"y = 2")]
            with tempfile.TemporaryDirectory() as scratch:
                cache = os.path.join(scratch, "cache.jsonl")
                detectors.run_deep(additions, cache)
                (path,) = [os.path.join(scratch, n) for n in os.listdir(scratch)]
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write('{"file": "c.py", "find')  # a write cut short
                flags, _ = detectors.run_deep(additions, cache)
                self.assertEqual(flags.findings, 0)
                with open(path, encoding="utf-8") as handle:
                    lines = handle.read().splitlines()
                self.assertEqual(len(lines), 3)  # two records plus the broken one, now on its own line
        finally:
            os.environ.pop("LEFTBLOCK_DEEP_DETECTOR", None)
            sys.path.pop(0)


class CompareTests(unittest.TestCase):
    def results(self, recall):
        rate = {"value": recall, "lo": 0.0, "hi": 1.0, "n": 10}
        entry = {"overall": {"recall": rate, "precision": rate}, "critical": {"recall": rate, "precision": rate}}
        return {"datasets": {"d": {"full_files": {"detectors": {"gitleaks-stock": entry}}, "seconds_total": 3}},
                "provenance": {"gitleaks": {"version": "8.30.1"}}}

    def test_identical_files_show_no_differences(self):
        text = compare.render(self.results(0.5), self.results(0.5))
        self.assertIn("0 of", text)
        self.assertIn("None: same pins", text)

    def test_a_changed_value_and_a_changed_input_are_listed(self):
        other = self.results(0.6)
        other["provenance"]["gitleaks"]["version"] = "9.0.0"
        text = compare.render(self.results(0.5), other)
        self.assertIn("50.0%", text)
        self.assertIn("60.0%", text)
        self.assertIn("gitleaks.version", text)

    def test_smoke_samples_are_not_compared(self):
        def with_sample(results, smoke):
            rate = {"value": 0.5, "lo": 0.0, "hi": 1.0, "n": 1}
            entry = {"overall": {"recall": rate, "precision": rate}, "critical": {"recall": rate, "precision": rate}}
            results["datasets"]["d"]["windows"] = {"detectors": {"deep-scan": entry}, "sample": {"sha256": "x", "smoke_files": smoke}}
            return results
        text = compare.render(with_sample(self.results(0.5), None), with_sample(self.results(0.5), 40))
        self.assertIn("not compared", text)
        self.assertNotIn("| d | windows |", text)

    def test_timings_are_ignored(self):
        other = self.results(0.5)
        other["datasets"]["d"]["seconds_total"] = 999
        self.assertIn("0 of", compare.render(self.results(0.5), other))


if __name__ == "__main__":
    unittest.main()
