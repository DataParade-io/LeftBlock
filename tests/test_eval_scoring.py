"""Unit tests for the evaluation harness: scorer, intervals, tier mapping, sampling, data-dir guard."""

import os
import random
import subprocess
import tempfile
import unittest

from eval import creddata, datadir, scoring, stats, tiers, windows


def unit(file, start, truth, categories, end=None, weight=1.0):
    return scoring.make_unit(file, start, end or start, truth, categories, weight=weight)


class WilsonTests(unittest.TestCase):
    def test_known_interval(self):
        lo, hi = stats.wilson(0.5, 100)
        self.assertAlmostEqual(lo, 0.4038, places=3)
        self.assertAlmostEqual(hi, 0.5962, places=3)

    def test_extremes_stay_inside_zero_and_one(self):
        lo, hi = stats.wilson(1.0, 10)
        self.assertLess(lo, 1.0)
        self.assertAlmostEqual(hi, 1.0)
        lo, hi = stats.wilson(0.0, 10)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.0)

    def test_no_trials_is_uninformative(self):
        self.assertEqual(stats.wilson(0.0, 0), (0.0, 1.0))
        self.assertIsNone(stats.rate([], [])["value"])

    def test_unit_weights_match_plain_counts(self):
        r = stats.rate([1.0] * 30, [1.0] * 40)
        self.assertAlmostEqual(r["value"], 0.75)
        lo, hi = stats.wilson(0.75, 40)
        self.assertAlmostEqual(r["lo"], lo)
        self.assertAlmostEqual(r["hi"], hi)

    def test_weights_correct_the_estimate_and_widen_the_interval(self):
        # 10 hits of weight 1 and 10 misses of weight 9: true rate is 10/100, not 10/20.
        r = stats.rate([1.0] * 10, [1.0] * 10 + [9.0] * 10)
        self.assertAlmostEqual(r["value"], 10 / 100)
        plain = stats.wilson(0.5, 20)
        self.assertGreater(r["hi"] - r["lo"], 0)
        self.assertLess(stats.effective_n([1.0] * 10 + [9.0] * 10), 20)
        self.assertNotEqual(r["lo"], plain[0])


class ScoringTests(unittest.TestCase):
    def test_merge_prefers_true_then_false_and_excludes_x_only_ranges(self):
        rows = [
            ("f", 1, 1, "F", ["Password"]),
            ("f", 1, 1, "T", ["Key"]),
            ("f", 2, 2, "X", ["Other"]),
            ("f", 3, 3, "X", ["Other"]),
            ("f", 3, 3, "F", ["UUID"]),
        ]
        units, excluded = scoring.merge_rows(rows)
        self.assertEqual(excluded, 1)
        self.assertEqual([(u.start, u.truth, u.categories) for u in units], [(1, "T", ("Key",)), (3, "F", ("UUID",))])

    def test_hit_when_a_finding_overlaps_any_line_of_the_range(self):
        units = [unit("a", 5, "T", ["PEM Private Key"], end=9), unit("a", 20, "T", ["Password"])]
        self.assertEqual(scoring.hit_units(units, {("a", 7)}), {0})
        self.assertEqual(scoring.hit_units(units, {("b", 20), ("a", 21)}), set())

    def test_metrics_counts_and_rates(self):
        units = [unit("a", 1, "T", ["Password"]), unit("a", 2, "T", ["Password"]),
                 unit("a", 3, "F", ["Password"]), unit("a", 4, "F", ["Password"])]
        m = scoring.metrics(units, {0, 2})
        self.assertEqual(m["counts"], {"tp": 1, "fp": 1, "fn": 1, "tn": 1})
        self.assertAlmostEqual(m["recall"]["value"], 0.5)
        self.assertAlmostEqual(m["precision"]["value"], 0.5)

    def test_no_hits_leaves_precision_undefined(self):
        m = scoring.metrics([unit("a", 1, "T", ["Password"])], set())
        self.assertEqual(m["recall"]["value"], 0.0)
        self.assertIsNone(m["precision"]["value"])

    def test_weighted_metrics_estimate_the_population(self):
        units = [unit("a", 1, "T", ["Key"], weight=1.0), unit("a", 2, "F", ["Key"], weight=9.0)]
        m = scoring.metrics(units, {0, 1})
        self.assertAlmostEqual(m["precision"]["value"], 0.1)
        self.assertEqual(m["counts"]["fp"], 1)
        self.assertEqual(m["estimated"]["fp"], 9.0)

    def test_breakdown_counts_a_unit_under_each_category_but_once_overall(self):
        units = [unit("a", 1, "T", ["Password", "Key"]), unit("a", 2, "T", ["Salt"])]
        result = scoring.breakdown(units, {0})
        self.assertEqual(result["overall"]["counts"]["tp"], 1)
        self.assertEqual(result["categories"]["Password"]["counts"]["tp"], 1)
        self.assertEqual(result["categories"]["Key"]["counts"]["tp"], 1)
        self.assertEqual(result["categories"]["Salt"]["counts"]["fn"], 1)


class TierTests(unittest.TestCase):
    def test_every_group_is_named_and_categories_are_unique(self):
        names = [n for names in tiers.CRITICAL_GROUPS.values() for n in names]
        self.assertEqual(len(names), len(set(names)))
        for group in ("cloud_keys", "private_keys", "provider_tokens", "passwords", "auth_headers"):
            self.assertIn(group, tiers.CRITICAL_GROUPS)

    def test_the_tier_covers_the_named_credential_types(self):
        for category, group in {
            "AWS Client ID": "cloud_keys", "AWS Multi": "cloud_keys", "Azure Access Token": "cloud_keys",
            "Google API Key": "cloud_keys", "PEM Private Key": "private_keys", "JWK": "private_keys",
            "BASE64 Private Key": "private_keys", "Slack Token": "provider_tokens", "Password": "passwords",
            "SQL Password": "passwords", "CMD Password": "passwords", "URL Credentials": "passwords",
            "Basic Authorization": "auth_headers", "Bearer Authorization": "auth_headers", "JSON Web Token": "auth_headers",
        }.items():
            self.assertEqual(tiers.group_of(category), group, category)
            self.assertEqual(tiers.tier_of([category]), tiers.CRITICAL)

    def test_generic_and_non_secret_categories_are_not_critical(self):
        for category in ("Key", "Token", "API", "Secret", "Auth", "Credential"):
            self.assertEqual(tiers.tier_of([category]), tiers.BROAD)
        for category in ("UUID", "Nonce", "Salt", "AWS S3 Bucket", "Other", "NKEY Seed"):
            self.assertEqual(tiers.tier_of([category]), tiers.OTHER)

    def test_any_critical_category_puts_the_line_in_the_tier(self):
        self.assertEqual(tiers.tier_of(["Key", "Password"]), tiers.CRITICAL)
        self.assertTrue(tiers.in_tier(["Key", "Password"], tiers.CRITICAL))
        self.assertTrue(tiers.in_tier(["Key"], tiers.BROAD))
        self.assertFalse(tiers.in_tier(["Key"], tiers.CRITICAL))
        self.assertFalse(tiers.in_tier(["UUID"], tiers.BROAD))

    def test_every_provider_rule_of_the_shipped_ruleset_has_a_generated_category(self):
        from eval import generated
        for kind, (category, *_rest) in generated.KINDS.items():
            if kind in ("password", "db-url", "jwt", "pem", "aws-access", "aws-secret", "google", "github", "slack", "stripe"):
                continue
            self.assertEqual(tiers.group_of(category), "provider_tokens", category)


class SamplingTests(unittest.TestCase):
    def setUp(self):
        self.units = (
            [unit("c%d" % i, 1, "T", ["Password"]) for i in range(50)]
            + [unit("k%d" % i, 1, "T", ["Salt"]) for i in range(40)]
            + [unit("f%d" % i, 1, "F", ["Password"]) for i in range(200)]
            + [unit("g%d" % i, 1, "F", ["Key"]) for i in range(100)]
        )

    def test_every_critical_true_unit_is_taken_with_weight_one(self):
        sample = creddata.select_sample(self.units, 30, seed=1)
        taken = {u.file for u in sample if u.truth == "T" and u.categories == ("Password",)}
        self.assertEqual(len(taken), 50)
        self.assertTrue(all(u.weight == 1.0 for u in sample if u.categories == ("Password",) and u.truth == "T"))

    def test_weights_recover_the_population_per_stratum(self):
        sample = creddata.select_sample(self.units, 30, seed=1)
        for truth, category, size in (("F", "Password", 200), ("F", "Key", 100), ("T", "Salt", 40)):
            members = [u for u in sample if u.truth == truth and u.categories == (category,)]
            self.assertAlmostEqual(sum(u.weight for u in members), size)

    def test_deterministic_for_a_seed_and_different_across_seeds(self):
        a = creddata.select_sample(self.units, 30, seed=1)
        self.assertEqual(a, creddata.select_sample(self.units, 30, seed=1))
        self.assertNotEqual(a, creddata.select_sample(self.units, 30, seed=2))

    def test_small_strata_keep_a_minimum(self):
        units = self.units + [unit("r%d" % i, 1, "F", ["Nonce"]) for i in range(10)]
        sample = creddata.select_sample(units, 10, seed=1)
        self.assertGreaterEqual(len([u for u in sample if u.categories == ("Nonce",)]), creddata.MIN_PER_STRATUM)


class WindowTests(unittest.TestCase):
    def test_windows_widen_by_the_radius_and_merge(self):
        units = [unit("a", 10, "T", ["Key"]), unit("a", 14, "T", ["Key"]), unit("a", 50, "T", ["Key"], end=52)]
        result = windows.window_lines(units, {"a": 100}, 5)
        self.assertEqual(result["a"], list(range(5, 20)) + list(range(45, 58)))

    def test_windows_are_clipped_to_the_file(self):
        result = windows.window_lines([unit("a", 2, "T", ["Key"])], {"a": 4}, 5)
        self.assertEqual(result["a"], [1, 2, 3, 4])

    def test_blanked_copy_keeps_line_numbers(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            with open(os.path.join(src, "f.txt"), "wb") as handle:
                handle.write(b"one\ntwo\nthree\nfour\nfive\n")
            windows.write_blanked(src, out, {"f.txt": [2, 3]})
            with open(os.path.join(out, "f.txt"), "rb") as handle:
                self.assertEqual(handle.read().split(b"\n")[:5], [b"", b"two", b"three", b"", b""])
            self.assertEqual([(n, t) for _, n, t in windows.additions(src, {"f.txt": [1, 3]})], [(1, b"one"), (3, b"three")])


class DataDirTests(unittest.TestCase):
    def test_inside_a_git_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            subprocess.run(["git", "init", "-q", root], check=True)
            with self.assertRaises(datadir.DataDirError):
                datadir.require_outside_git(os.path.join(root, "not-yet-created", "data"))

    def test_outside_a_repository_is_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(datadir.require_outside_git(root), os.path.realpath(root))


class GeneratedCorpusTests(unittest.TestCase):
    def test_generation_is_deterministic_and_labels_point_at_the_planted_lines(self):
        from eval import generated
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            units_a, info = generated.generate(a, 7)
            units_b, _ = generated.generate(b, 7)
            self.assertEqual(units_a, units_b)
            self.assertEqual(len(units_a), info["files"])
            self.assertEqual({u.truth for u in units_a}, {"T", "F"})
            for u in units_a[:40]:
                self.assertTrue(os.path.isfile(os.path.join(a, u.file)))
                self.assertGreaterEqual(u.start, 1)
                self.assertGreaterEqual(u.end, u.start)

    def test_a_different_seed_gives_different_content(self):
        from eval import generated
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            ua, _ = generated.generate(a, 1)
            ub, _ = generated.generate(b, 2)
            first = ua[0].file
            with open(os.path.join(a, first)) as fa, open(os.path.join(b, first)) as fb:
                self.assertNotEqual(fa.read(), fb.read())


if __name__ == "__main__":
    unittest.main()
