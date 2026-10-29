"""Recorded per-finding overrides, using synthetic data and disposable repos."""

import hashlib
import json
import re
import unittest
from importlib.metadata import version

import yaml

from test_commit_gate import GITLEAKS, RepositoryFixture

# Flagged by the shipped personal-email rule; the rule allowlists only
# example.* and GitHub identities.
EMAIL = "info" + "@" + "public-role" + ".co"
OTHER_EMAIL = "help" + "@" + "public-role" + ".co"
PAGE = "page.tsx"
REASON = "Public role address for the site"


@unittest.skipUnless(GITLEAKS, "Gitleaks must be installed for actual scanner tests")
class RecordedOverrideTests(RepositoryFixture):
    def setUp(self):
        super().setUp()
        proc = self.leftblock("install", "--local", "--check-only", "--gitleaks", GITLEAKS)
        self.assertEqual(proc.returncode, 0, "Local install failed")

    def write_stage(self, text, name=PAGE):
        (self.repo / name).write_text(text)
        self.git("add", name, check=True)

    def check(self):
        policy = self.repo / ".git" / "leftblock" / "policy.json"
        return self.leftblock("check", "--config", str(policy))

    def plain_check(self, *extra):
        # No --config: `check` must pick up the local install policy by itself.
        return self.leftblock("check", *extra)

    def ids(self, proc):
        # Per-finding detail lines (the final summary line repeats the ids).
        return re.findall(r"^      .*\[id ([0-9a-f]{16})\](?: \(.*\))?$", proc.stderr, re.MULTILINE)

    def blocked_id(self, text=None):
        self.write_stage(text or f"a\nContact: {EMAIL}\n")
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        ids = self.ids(proc)
        self.assertEqual(len(ids), 1)
        return ids[0]

    def allow(self, *ids, reason=REASON):
        return self.leftblock("allow", *ids, "--reason", reason)

    def test_block_output_has_id_and_instructions_but_no_value(self):
        ident = self.blocked_id()
        proc = self.check()
        out = proc.stdout + proc.stderr
        self.assertIn(f"allow {ident}", out)
        self.assertIn("record a reviewed override", out)
        self.assertIn("--reason", out)
        self.assertNotIn(EMAIL, out)
        self.assertNotIn("public-role", out)
        self.assertNotIn("No approval override", out)

    def test_last_line_alone_names_the_finding_and_next_step(self):
        # Wrappers such as `kbs commit` often show only the final line.
        ident = self.blocked_id()
        last = self.check().stderr.strip().splitlines()[-1]
        self.assertIn("Inspection blocked", last)
        self.assertIn(f"leftblock-personal-email in {PAGE}:2 [id {ident}]", last)
        self.assertIn("Remove the flagged content", last)
        self.assertIn(f"allow {ident}", last)
        self.assertNotIn("\033[", last)  # captured output carries no colour codes

    def test_allow_stages_entry_then_check_passes_and_reports(self):
        ident = self.blocked_id()
        proc = self.allow(ident)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        staged = self.git("show", ":.leftblock-allow.yml", check=True).stdout
        data = yaml.safe_load(staged)
        self.assertEqual(data["version"], 1)
        entry = data["allow"][0]
        self.assertEqual(
            (entry["id"], entry["rule"], entry["file"], entry["reason"]),
            (ident, "leftblock-personal-email", PAGE, REASON),
        )
        self.assertNotIn(EMAIL, staged)
        check = self.check()
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("Override applied", check.stderr)
        self.assertIn(ident, check.stderr)
        self.assertIn(REASON, check.stderr)
        # Overrides stay visible on every run, and the commit goes through.
        self.assertEqual(self.git("commit", "-m", "test: allowed").returncode, 0)

    def test_findings_show_line_and_category_and_allow_records_kind(self):
        ident = self.blocked_id()
        proc = self.check()
        detail = [l for l in proc.stderr.splitlines() if l.startswith("      ")]
        self.assertEqual(detail, [
            f"      {PAGE}:2: leftblock-personal-email [id {ident}] (Personal email address)",
            "      Hint: Use a role address or a reserved placeholder (example.com/.org/.net, or any .test, .example or .invalid domain), or describe it instead.",
        ])
        self.assertIn(f"leftblock-personal-email in {PAGE}:2 [id {ident}]", proc.stderr.splitlines()[-1])
        self.assertNotIn(EMAIL, proc.stdout + proc.stderr)
        self.assertEqual(self.allow(ident).returncode, 0)
        text = (self.repo / ".leftblock-allow.yml").read_text()
        self.assertIn('kind: "Personal email address"', text)
        entry = yaml.safe_load(text)["allow"][0]
        self.assertEqual(entry["kind"], "Personal email address")
        # kind is informational: an entry without it still matches.
        (self.repo / ".leftblock-allow.yml").write_text(
            "\n".join(l for l in text.splitlines() if not l.strip().startswith("kind:")) + "\n"
        )
        self.git("add", ".leftblock-allow.yml", check=True)
        self.assertEqual(self.check().returncode, 0)

    def test_version_flag_prints_the_installed_version(self):
        proc = self.leftblock("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "leftblock " + version("leftblock"))

    def test_blocked_output_starts_with_version_and_ruleset_hash(self):
        ident = self.blocked_id()
        rules = (self.repo / ".git" / "leftblock" / "gitleaks.toml").read_bytes()
        first = self.check().stderr.splitlines()[0]
        self.assertTrue(
            first.endswith(f"leftblock {version('leftblock')}, ruleset {hashlib.sha256(rules).hexdigest()[:12]}"),
            first,
        )
        # Still first when an override is also applied.
        self.assertEqual(self.allow(ident).returncode, 0)
        self.write_stage(f"a\nContact: {EMAIL}\nOther: {OTHER_EMAIL}\n")
        lines = self.check().stderr.splitlines()
        self.assertIn("ruleset", lines[0])
        self.assertIn("Override applied", lines[1])

    def test_ruleset_is_unknown_without_a_gitleaks_config_argument(self):
        from leftblock import cli
        self.assertEqual(cli.ruleset_id({"checkers": [{"command": "scanner --fast"}]}, str(self.repo)), "unknown")
        self.assertEqual(cli.ruleset_id({"checkers": [{"command": "scanner --config nope.toml"}]}, str(self.repo)), "unknown")
        self.assertEqual(cli.ruleset_id({}, str(self.repo)), "unknown")

    def test_check_defaults_to_the_local_policy_and_is_a_dry_run(self):
        self.write_stage(f"a\nContact: {EMAIL}\n")
        before = self.git("write-tree", check=True).stdout
        proc = self.plain_check()
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("leftblock-personal-email", proc.stderr)
        self.assertRegex(proc.stderr, r"Re-run this check: .*leftblock.* check\n")
        self.assertNotIn("check --config", proc.stderr)  # the default policy needs no flag
        self.assertEqual(before, self.git("write-tree", check=True).stdout)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.baseline)
        self.assertEqual(self.git("diff", "--cached", "--name-only").stdout.strip(), PAGE)

    def test_local_policy_wins_over_a_root_policy_by_default(self):
        (self.repo / ".leftblock.yml").write_text(
            "version: 1\ncheckers:\n  - type: command\n    command: /usr/bin/true\n"
        )
        self.write_stage(f"a\nContact: {EMAIL}\n")
        self.assertEqual(self.plain_check().returncode, 1)

    def test_json_passed_exit_0(self):
        self.write_stage("nothing sensitive here\n")
        proc = self.plain_check("--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report, {
            "version": version("leftblock"), "result": "passed", "findings": [],
            "overrides_applied": [], "errors": [], "override_command": None,
        })
        self.assertIn("All configured checks passed", proc.stderr)

    def test_json_blocked_exit_1_and_text_mode_keeps_stdout_empty(self):
        ident = self.blocked_id()
        proc = self.plain_check("--format", "json")
        self.assertEqual(proc.returncode, 1)
        report = json.loads(proc.stdout)
        self.assertEqual(report["result"], "blocked")
        self.assertEqual(report["findings"], [{
            "file": PAGE, "line": 2, "rule": "leftblock-personal-email", "id": ident,
            "description": "Personal email address",
        }])
        self.assertEqual(report["errors"], [])
        self.assertIn(f"allow {ident}", report["override_command"])
        self.assertIn("--reason", report["override_command"])
        self.assertNotIn(EMAIL, proc.stdout + proc.stderr)
        self.assertIn("Inspection blocked", proc.stderr.splitlines()[-1])
        text = self.plain_check()
        self.assertEqual((text.returncode, text.stdout), (1, ""))

    def test_json_lists_applied_overrides(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        report = json.loads(self.plain_check("--format", "json").stdout)
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["overrides_applied"], [{
            "file": PAGE, "rule": "leftblock-personal-email", "id": ident, "reason": REASON,
        }])

    def test_json_error_exit_2_for_invalid_allow_file_and_bad_config(self):
        self.write_stage("nothing sensitive here\n")
        (self.repo / ".leftblock-allow.yml").write_text("version: 2\nallow: []\n")
        self.git("add", ".leftblock-allow.yml", check=True)
        for args in (("--format", "json"), ()):
            proc = self.plain_check(*args)
            self.assertEqual(proc.returncode, 2, proc.stderr)
        report = json.loads(self.plain_check("--format", "json").stdout)
        self.assertEqual(report["result"], "error")
        self.assertEqual([e["checker"] for e in report["errors"]], ["leftblock-allow"])
        self.assertIn("Invalid .leftblock-allow.yml", report["errors"][0]["message"])
        missing = self.leftblock("check", "--config", str(self.repo / "missing.json"), "--format", "json")
        self.assertEqual(missing.returncode, 2)
        report = json.loads(missing.stdout)
        self.assertEqual((report["result"], report["errors"][0]["checker"]), ("error", "configuration"))
        self.assertEqual(self.leftblock("check", "--config", str(self.repo / "missing.json")).returncode, 2)

    def test_allow_file_itself_is_not_flagged_and_dedupes(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.assertEqual(self.allow(ident).returncode, 0)
        data = yaml.safe_load((self.repo / ".leftblock-allow.yml").read_text())
        self.assertEqual(len(data["allow"]), 1)
        scan = self.check()
        self.assertEqual(scan.returncode, 0, scan.stderr)
        # Not the hex id, but the file as a whole: a numeric-looking id stays a string.
        self.assertIsInstance(data["allow"][0]["id"], str)

    def test_new_email_in_same_file_still_blocks(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.write_stage(f"a\nContact: {EMAIL}\nAlso: {OTHER_EMAIL}\n")
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(len(self.ids(proc)), 1)
        self.assertNotIn(ident, self.ids(proc))

    def test_unrelated_edit_to_allowed_line_stays_allowed(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.write_stage(f"a\nWrite to: {EMAIL} (public role address)\n")
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(ident, proc.stderr)

    def test_changed_allowed_value_reblocks(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.write_stage(f"a\nContact: {OTHER_EMAIL}\n")
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(ident, self.ids(proc))

    def test_same_value_on_two_lines_is_one_override(self):
        self.write_stage(f"Contact: {EMAIL}\nAgain: {EMAIL}\n")
        ids = self.ids(self.check())
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(self.allow(ids[0]).returncode, 0)
        self.assertEqual(self.check().returncode, 0)

    def test_legacy_line_based_id_still_allows_an_unchanged_line(self):
        line = f"Contact: {EMAIL}"
        self.blocked_id(f"a\n{line}\n")
        legacy = hashlib.sha256(f"leftblock-personal-email\0{PAGE}\0{line}".encode()).hexdigest()[:16]
        (self.repo / ".leftblock-allow.yml").write_text(
            'version: 1\nallow:\n  - id: "%s"\n    rule: "leftblock-personal-email"\n'
            '    file: "%s"\n    reason: "Public role address for the site"\n' % (legacy, PAGE)
        )
        self.git("add", ".leftblock-allow.yml", check=True)
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(legacy, proc.stderr)
        # A legacy entry still re-blocks when the line changes.
        self.write_stage(f"a\nWrite to: {EMAIL}\n")
        self.assertNotEqual(self.check().returncode, 0)

    def test_line_numbers_inside_modified_committed_file(self):
        self.write_stage("one\ntwo\nthree\n")
        self.git("commit", "-m", "test: base", check=True)
        ident = self.blocked_id(f"one\ntwo\nthree\nContact: {EMAIL}\n")
        self.assertEqual(self.allow(ident).returncode, 0)
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_reason_too_short_or_missing_is_refused(self):
        ident = self.blocked_id()
        for reason in ("", "   short  "):
            with self.subTest(reason=reason):
                proc = self.allow(ident, reason=reason)
                self.assertEqual(proc.returncode, 1)
        missing = self.leftblock("allow", ident)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("at least 10 characters", missing.stderr)
        self.assertNotIn("usage:", missing.stderr)
        self.assertFalse((self.repo / ".leftblock-allow.yml").exists())

    def index_blob(self):
        return self.git("ls-files", "--stage", "--", ".leftblock-allow.yml").stdout

    def test_reason_repeating_value_is_refused_and_restored_when_absent(self):
        ident = self.blocked_id()
        proc = self.allow(ident, reason=f"Public address {EMAIL} on the site")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("The reason would itself be flagged (rule leftblock-personal-email)", proc.stderr)
        self.assertIn("describe it instead", proc.stderr)
        self.assertFalse((self.repo / ".leftblock-allow.yml").exists())
        self.assertEqual(self.index_blob(), "")

    def test_reason_repeating_value_restores_existing_entries(self):
        first = self.blocked_id()
        self.assertEqual(self.allow(first).returncode, 0)
        path = self.repo / ".leftblock-allow.yml"
        before, staged = path.read_bytes(), self.index_blob()
        self.write_stage(f"x\nContact: {OTHER_EMAIL}\n", name="second.tsx")
        proc = self.check()
        second = [i for i in self.ids(proc) if i != first]
        self.assertEqual(len(second), 1)
        # Unstaged edit to the file must also survive a refused attempt.
        path.write_bytes(before + b"# local note\n")
        before = path.read_bytes()
        refused = self.allow(second[0], reason=f"It is {OTHER_EMAIL} really")
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.index_blob(), staged)

    def test_finding_in_allow_file_has_no_id_and_friendly_message(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        path = self.repo / ".leftblock-allow.yml"
        path.write_text(path.read_text().replace(REASON, f"Address {EMAIL} is public"))
        self.git("add", ".leftblock-allow.yml", check=True)
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.ids(proc), [])
        self.assertIn(
            "A reason in .leftblock-allow.yml contains a flagged value; "
            "reword that reason (don't repeat the value).", proc.stderr)
        self.assertNotIn("allow ", proc.stderr.split("blocked")[-1])

    def test_hand_edited_entry_with_empty_reason_blocks_as_invalid(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        path = self.repo / ".leftblock-allow.yml"
        data = yaml.safe_load(path.read_text())
        data["allow"][0]["reason"] = ""
        path.write_text(yaml.safe_dump(data))
        self.git("add", ".leftblock-allow.yml", check=True)
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Invalid .leftblock-allow.yml", proc.stderr)

    def test_invalid_allow_files_block_even_on_clean_content(self):
        self.write_stage("Harmless.\n")
        path = self.repo / ".leftblock-allow.yml"
        bad = (
            "version: [",
            "version: 2\nallow: []\n",
            "version: 1\nallow:\n  - rule: r\n    file: f\n    reason: long enough reason\n",
        )
        for text in bad:
            with self.subTest(text=text):
                path.write_text(text)
                self.git("add", ".leftblock-allow.yml", check=True)
                proc = self.check()
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("Invalid .leftblock-allow.yml", proc.stderr)

    def test_unstaged_allow_file_has_no_effect(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.git("reset", "-q", "--", ".leftblock-allow.yml", check=True)
        self.assertTrue((self.repo / ".leftblock-allow.yml").exists())
        proc = self.check()
        self.assertNotEqual(proc.returncode, 0)

    def test_unknown_id_is_refused(self):
        self.blocked_id()
        proc = self.allow("0123456789abcdef")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse((self.repo / ".leftblock-allow.yml").exists())

    def test_allow_does_not_commit(self):
        ident = self.blocked_id()
        self.assertEqual(self.allow(ident).returncode, 0)
        self.assert_not_committed()


class OverrideNeverCoversErrorsTests(RepositoryFixture):
    def test_missing_scanner_is_not_overridden(self):
        self.stage(f"Contact: {EMAIL}\n")
        self.policy("definitely-missing-scanner-binary --scan")
        entry = {
            "version": 1,
            "allow": [{"id": "0123456789abcdef", "rule": "x", "file": "fixture.txt",
                       "reason": "A long enough reason."}],
        }
        (self.repo / ".leftblock-allow.yml").write_text(yaml.safe_dump(entry))
        self.git("add", ".leftblock-allow.yml", check=True)
        self.assertNotEqual(self.leftblock("check").returncode, 0)
        proc = self.leftblock("allow", "0123456789abcdef", "--reason", REASON)
        self.assertEqual(proc.returncode, 1)

    def test_error_result_with_matching_entry_stays_blocked(self):
        from leftblock.allow import apply_allowlist
        from leftblock.core import CheckerResult
        result = CheckerResult("s", False, [{"File": "f", "RuleID": "r", "id": "a" * 16}], error=True)
        entries = [{"id": "a" * 16, "rule": "r", "file": "f", "reason": "A long enough reason."}]
        self.assertEqual(apply_allowlist([result], entries), [])
        self.assertFalse(result.clean)


if __name__ == "__main__":
    unittest.main()


class CommandPrefixTests(unittest.TestCase):
    def test_printed_command_never_contains_the_home_directory(self):
        import os
        from leftblock import cli
        home = os.path.expanduser("~")
        for prefix in (cli.command_prefix(), cli.shell_path(os.path.join(home, "x", "policy.json"))):
            self.assertNotIn(home + os.sep, prefix)
