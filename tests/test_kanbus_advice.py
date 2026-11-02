"""Per-rule advice and Kanbus board data, committed through the real hook."""

import json
import random
import unittest
import uuid

from leftblock import cli
from test_commit_gate import GITLEAKS, RepositoryFixture


def make_uuid(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


class RuleHintTests(unittest.TestCase):
    def test_every_shipped_rule_has_a_hint_and_key_rules_say_rotate(self):
        from pathlib import Path
        import re
        rules = (Path(cli.__file__).parent / "data" / "gitleaks.toml").read_text()
        shipped = set(re.findall(r'^id = "(leftblock-[a-z0-9-]+)"', rules, re.MULTILINE))
        from leftblock import bypass
        self.assertEqual(shipped | {bypass.MARKER_RULE, bypass.IGNORE_RULE}, set(cli.RULE_HINTS))
        for rule in ("openai-key", "anthropic-key", "eth-private-key", "wif-key", "bip39-mnemonic"):
            self.assertIn("rotate", cli.RULE_HINTS["leftblock-" + rule])
        self.assertIn("relative path", cli.RULE_HINTS["leftblock-home-path-posix"])
        self.assertIn("reserved placeholder", cli.RULE_HINTS["leftblock-personal-email"])


@unittest.skipUnless(GITLEAKS, "Gitleaks must be installed for actual scanner tests")
class KanbusBoardTests(RepositoryFixture):
    def setUp(self):
        super().setUp()
        proc = self.leftblock("install", "--local", "--check-only", "--gitleaks", GITLEAKS)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.rng = random.Random(4242)

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git("add", name, check=True)

    def board(self, description=""):
        project = make_uuid(self.rng)
        issue_id = "kanbus-" + make_uuid(self.rng)
        comment = make_uuid(self.rng)
        issue = {
            "id": issue_id, "title": "Synthetic board item", "description": description,
            "type": "task", "status": "open", "priority": 2, "assignee": None,
            "parent": "kanbus-" + make_uuid(self.rng), "labels": [], "dependencies": [],
            "comments": [{"id": comment, "author": "agent", "text": "note", "created_at": "2026-10-20T10:00:00Z"}],
            "created_at": "2026-10-20T10:00:00Z", "updated_at": "2026-10-20T10:00:00Z",
        }
        event = {
            "schema_version": 1, "event_id": make_uuid(self.rng), "issue_id": issue_id,
            "event_type": "issue_created", "occurred_at": "2026-10-20T10:00:00.000Z",
            "actor" + "_id": "agent", "payload": {"title": "Synthetic board item"},
        }
        self.write(".kanbus.yml", f"project_key: kanbus\nproject_id: {project}\n")
        self.write(f"project/issues/{issue_id}.json", json.dumps(issue, indent=2))
        self.write(f"project/events/2026-10-20T10-00-00.000Z__{event['event_id']}.json", json.dumps(event, indent=2))
        return issue_id

    def test_realistic_kanbus_board_data_commits_through_the_hook(self):
        self.board()
        proc = self.git("commit", "-m", "test: board data")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.baseline)

    def test_home_path_in_an_issue_still_blocks_and_points_at_kbs(self):
        home_path = "/" + "Users/someone/notes"
        issue_id = self.board(description="See " + home_path + " for details")
        head = self.git("rev-parse", "HEAD").stdout
        proc = self.git("commit", "-m", "test: board data")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout, head)
        self.assertIn(f"project/issues/{issue_id}.json:", proc.stderr)
        self.assertIn("leftblock-home-path-posix", proc.stderr)
        self.assertIn("Hint: Use a relative path, $HOME or ~ instead.", proc.stderr)
        self.assertEqual(
            proc.stderr.count("This issue file is written by Kanbus; fix the content with kbs update"), 1,
        )
        self.assertNotIn(home_path, proc.stdout + proc.stderr)

    def test_event_file_hint_says_delete_and_recreate_not_update(self):
        self.write("project/events/2026-10-20T10-00-00.000Z__x.json",
                   '{\n  "note": "see /' + 'Users/someone/notes"\n}\n')
        proc = self.leftblock("check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("append-only history", proc.stderr)
        self.assertIn("kbs delete <issue id>", proc.stderr)
        self.assertNotIn("kbs update", proc.stderr)

    def test_event_and_issue_text_with_aws_ids_or_emails_blocks_through_the_hook(self):
        """Board data is scanned through the hook: events as well as issues."""
        account = "7" + "".join(str(self.rng.randrange(10)) for _ in range(11))
        email = "jane." + "doe@" + "example-corp" + ".co"
        cases = {
            "project/events/2026-10-20T10-00-00.000Z__a.json": (
                {"event_type": "comment_added", "payload": {"comment_text": "in account %s now" % account}},
                "leftblock-aws-account-id", account),
            "project/events/2026-10-20T10-00-00.000Z__b.json": (
                {"event_type": "comment_added", "payload": {"comment_text": "ask %s" % email}},
                "leftblock-personal-email", email),
            "project/issues/kanbus-a.json": (
                {"id": "kanbus-a", "description": "role arn:aws:iam::%s:role/x" % account},
                "leftblock-aws-account-id", account),
            "project/issues/kanbus-b.json": (
                {"id": "kanbus-b", "comments": [{"text": "ask %s" % email}]},
                "leftblock-personal-email", email),
        }
        for name, (doc, rule, value) in cases.items():
            with self.subTest(file=name):
                self.write(name, json.dumps(doc, indent=2))
                proc = self.leftblock("check")
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn(name + ":", proc.stderr)
                self.assertIn(rule, proc.stderr)
                self.assertNotIn(value, proc.stdout + proc.stderr)
                self.git("reset", "-q", "--", name)
                (self.repo / name).unlink()

    def test_hint_is_printed_once_per_rule(self):
        self.write("notes.md", "a /" + "Users/one/x\nb /" + "Users/two/y\n")
        proc = self.leftblock("check")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr.count("Hint: Use a relative path"), 1)
        self.assertNotIn("written by Kanbus", proc.stderr)


if __name__ == "__main__":
    unittest.main()
