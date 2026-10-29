"""Tests for the LeftBlock shipped gitleaks ruleset.

All fixtures are synthetic and generated at test time from a seeded RNG.
No real credential, wallet, or personal value is ever embedded here:
  - hex strings are random bytes,
  - WIF keys are random bytes with a computed version and checksum,
  - mnemonics are random draws from a subset of the real BIP-39
    wordlist (shape-identical to real seed phrases, but never a valid
    checksummed phrase for any wallet).
"""

import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULESET = PROJECT_ROOT / "leftblock" / "data" / "gitleaks.toml"

GITLEAKS = shutil.which("gitleaks")

# A subset of the real BIP-39 English wordlist (all <= 8 letters, the
# shape the mnemonic rule matches) used to synthesize phrases.
BIP39_SAMPLE_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "across", "action", "actor", "actual",
    "adapt", "address", "adjust", "admit", "advance", "advice", "afford",
    "afraid", "agent", "agree", "ahead", "airport", "aisle", "alarm",
    "album", "alert", "alien", "align", "alike", "alive", "allow", "alone",
]

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HEX = "0123456789abcdef"


def _rng():
    return random.Random(42)


def rand_hex(rng, n):
    return "".join(rng.choice(HEX) for _ in range(n))


def rand_base58(rng, n):
    return "".join(rng.choice(BASE58_ALPHABET) for _ in range(n))


def rand_wif(rng, compressed=True):
    """A valid WIF built from random bytes (never a real key)."""
    payload = b"\x80" + bytes(rng.randrange(256) for _ in range(32)) + (b"\x01" if compressed else b"")
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, out = int.from_bytes(raw, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        out = BASE58_ALPHABET[rest] + out
    return out


def rand_b58_secret(rng, n):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(n))


def rand_openai_like(rng, n):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    return "".join(rng.choice(alphabet) for _ in range(n))


def mnemonic(rng, n_words):
    return " ".join(rng.choice(BIP39_SAMPLE_WORDS) for _ in range(n_words))


def run_gitleaks(target: Path, report_path: Path):
    return subprocess.run(
        [
            GITLEAKS, "dir", str(target),
            "--config", str(RULESET),
            "--no-banner", "--redact",
            "--report-format", "json",
            "--report-path", str(report_path),
        ],
        capture_output=True, text=True,
    )


def scan_and_rule_ids(files: dict) -> list:
    """Write files into a temp dir, scan it, return sorted RuleIDs."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "repo"
        target.mkdir()
        for name, content in files.items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        report = Path(tmp) / "report.json"
        proc = run_gitleaks(target, report)
        if proc.returncode not in (0, 1):
            raise AssertionError(
                f"gitleaks failed (exit {proc.returncode}):\n{proc.stderr}"
            )
        if proc.returncode == 0:
            return []
        data = json.loads(report.read_text())
        return sorted({f["RuleID"] for f in data})


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class SensitiveFixtureTests(unittest.TestCase):
    """Every sensitive category must be caught by the shipped ruleset."""

    def test_personal_data_findings(self):
        rng = _rng()
        uuid = "-".join(rand_hex(rng, n) for n in (8, 4, 4, 4, 12))
        # Synthetic personal values are assembled at test time so this
        # test source is itself clean under the shipped ruleset.
        user = "jd" + "oe"
        email = "jane." + "doe@" + "example-corp" + ".co"
        findings = scan_and_rule_ids({
            "issues/one.json": (
                '{"assignee_email": "%s", "session_id": "%s",'
                ' "actor_id": "%s", "home": "/Users/%s/.cache"}'
                % (email, uuid, user, user)
            ),
            "notes/windows.md": "Cache lives at C:\\Users\\%s\\AppData.\n" % user,
            "notes/posix.md": "see /home/%s/build.log for details\n" % user,
        })
        self.assertIn("leftblock-personal-email", findings)
        self.assertIn("leftblock-session-uuid", findings)
        self.assertIn("leftblock-actor-id", findings)
        self.assertIn("leftblock-home-path-posix", findings)
        self.assertIn("leftblock-home-path-windows", findings)

    def test_llm_api_key_findings(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "keys_api.txt": "\n".join([
                "OPENAI_API_KEY=sk-" + rand_openai_like(rng, 48),
                "OPENAI_PROJECT_KEY=sk-proj-" + rand_openai_like(rng, 56),
                "OPENAI_SERVICE_KEY=sk-svcacct-" + rand_openai_like(rng, 56),
                "ANTHROPIC_API_KEY=sk-ant-api03-" + rand_openai_like(rng, 90),
                "GEMINI_API_KEY=AIza" + rand_openai_like(rng, 35),
            ]) + "\n",
        })
        self.assertIn("leftblock-openai-key", findings)
        self.assertIn("leftblock-anthropic-key", findings)
        # Gemini/Google AI keys ride the default gcp-api-key rule.
        self.assertIn("gcp-api-key", findings)

    def test_aws_credential_pair_findings(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "secrets.env": "\n".join([
                "AWS_ACCESS_KEY_ID=AKIA" + rand_openai_like(rng, 16).upper(),
                "AWS_SECRET_ACCESS_KEY=" + rand_b58_secret(rng, 40),
            ]) + "\n",
        })
        # gitleaks defaults catch the pair (generic-api-key / aws rules).
        self.assertTrue(
            set(findings) & {"aws", "generic-api-key"},
            f"expected aws or generic-api-key, got {findings}",
        )

    # ------------------------------------------------------------------
    # Crypto wallet material
    # ------------------------------------------------------------------

    def test_ethereum_private_keys_flagged(self):
        rng = _rng()
        bare = rand_hex(rng, 64)
        prefixed = "0x" + rand_hex(rng, 64)
        findings = scan_and_rule_ids({
            "wallet.txt": "\n".join([
                f"private_key = {bare}",
                f"eth_private_key = {prefixed}",
            ]) + "\n",
        })
        self.assertIn("leftblock-eth-private-key", findings)

    def test_wif_bitcoin_keys_flagged(self):
        rng = _rng()
        wif_compressed = rand_wif(rng)
        wif_uncompressed = rand_wif(rng, compressed=False)
        findings = scan_and_rule_ids({
            "wallet.txt": "\n".join([
                f"btc_wif = {wif_compressed}",
                f"btc_wif_uncompressed = {wif_uncompressed}",
            ]) + "\n",
        })
        self.assertIn("leftblock-wif-key", findings)

    def test_bip39_mnemonics_flagged(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "wallet.txt": "\n".join([
                f'seed_phrase = "{mnemonic(rng, 12)}"',
                f'recovery_phrase = "{mnemonic(rng, 12)}"',
                f'vault_seed = "{mnemonic(rng, 24)}"',
                f"recovery_mnemonic: {mnemonic(rng, 24)}",
            ]) + "\n",
        })
        self.assertIn("leftblock-bip39-mnemonic", findings)

    def test_quoted_assignment_mnemonic_shapes_flagged(self):
        # Locks in the real-world label shapes: `label = "words"` and
        # `label: words`, which must all match despite the quote/spacing.
        rng = _rng()
        p12 = mnemonic(rng, 12)
        findings = scan_and_rule_ids({
            "quoted.txt": f'seed_phrase = "{p12}"\n',
            "unquoted.txt": f"mnemonic: {mnemonic(rng, 15)}\n",
            "tight.txt": f'seed_phrase="{p12}"\n',
        })
        self.assertEqual(findings, ["leftblock-bip39-mnemonic"])

    def test_all_bip39_phrase_lengths_flagged(self):
        rng = _rng()
        files = {
            f"phrase_{n}.txt": f'seed phrase: {mnemonic(rng, n)}\n'
            for n in (12, 15, 18, 21, 24)
        }
        findings = scan_and_rule_ids(files)
        self.assertIn("leftblock-bip39-mnemonic", findings)
        self.assertEqual(len(findings), 1, f"unexpected rules: {findings}")


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class NegativeTests(unittest.TestCase):
    """Public wallet addresses and hash-like hex must NOT be flagged."""

    def test_no_reply_addresses_pass_but_lookalikes_still_flag(self):
        at = "@"
        self.assertEqual(scan_and_rule_ids({"CHANGELOG.md": "\n".join([
            "Co-Authored-By: Bot <noreply" + at + "vendor" + ".co" + ">",
            "From: no-reply" + at + "vendor" + ".co",
        ]) + "\n"}), [])
        self.assertEqual(scan_and_rule_ids({"notes.md": "mail jo" + at + "vendor" + ".co\n"}),
                         ["leftblock-personal-email"])
        self.assertEqual(scan_and_rule_ids({"notes.md": "mail notnoreply" + at + "vendor" + ".co\n"}),
                         ["leftblock-personal-email"])

    def test_reserved_placeholder_domains_pass_but_lookalikes_still_flag(self):
        at = "@"
        passing = [
            "person" + at + "example.invalid",
            "a" + at + "mail.acme.test",
            "b" + at + "deep.sub.host.example",
            "c" + at + "app.localhost",
            "d" + at + "example.edu",
            "e" + at + "x.test",
        ]
        self.assertEqual(scan_and_rule_ids({"notes.md": "\n".join("mail " + a for a in passing) + "\n"}), [])
        for domain in ["test" + ".com", "invalid" + ".org", "example.test" + ".co", "mytest" + ".dev",
                       "example" + ".edu.co", "notexample" + ".edu"]:
            with self.subTest(domain=domain):
                self.assertEqual(scan_and_rule_ids({"notes.md": "mail jo" + at + domain + "\n"}),
                                 ["leftblock-personal-email"])

    def test_public_wallet_addresses_and_hashes_not_flagged(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "addresses.txt": "\n".join([
                # Public Ethereum address: 0x + 40 hex (NOT a private key).
                "deposit address: 0x" + rand_hex(rng, 40),
                # Public Bitcoin address: base58 starting with 1.
                "btc address: 1" + rand_base58(rng, 33),
            ]) + "\n",
            "hashes.txt": "\n".join([
                # Bare 64-hex: shape-identical to a SHA-256 digest.
                "sha256: " + rand_hex(rng, 64),
                # 40-hex git SHA and 128-hex SHA-512.
                "commit " + rand_hex(rng, 40),
                "sha512: " + rand_hex(rng, 128),
            ]) + "\n",
        })
        self.assertEqual(findings, [], f"false positives: {findings}")

    def test_prose_and_clean_content_not_flagged(self):
        findings = scan_and_rule_ids({
            "README.md": "\n".join([
                "the team will review the release plan early tomorrow morning",
                "and confirm whether the database migration can proceed as planned",
                "Contact git@github.com or noreply@example.com with questions.",
                "Builds run under /Users/example/ci on the shared runner.",
            ]) + "\n",
            "src/main.rs": "\n".join([
                "fn main() {",
                '    let config_path = std::env::var("CONFIG_PATH");',
                '    println!("hello world");',
                "}",
            ]) + "\n",
            "config.toml": "[server]\nhost = \"0.0.0.0\"\nport = 8080\n",
        })
        self.assertEqual(findings, [], f"false positives: {findings}")

    def test_unlabeled_hex_blob_not_flagged(self):
        # A bare 64-hex string with NO key-like keyword context is left
        # alone (documented trade-off vs SHA-256/git-SHA false positives).
        rng = _rng()
        findings = scan_and_rule_ids({
            "blob.txt": rand_hex(rng, 64) + "\n",
        })
        self.assertEqual(findings, [], f"false positives: {findings}")


def load_ignore_fingerprints(tree: Path) -> set:
    """Fingerprint lines from the tree's .gitleaksignore, if present.

    gitleaks honors .gitleaksignore only for relative scan targets, but
    dogfood trees are usually absolute paths, so the test applies the
    ignore list itself: these are human-reviewed findings recorded by
    the tree's own maintainers.
    """
    ignore_file = tree / ".gitleaksignore"
    if not ignore_file.exists():
        return set()
    entries = set()
    for line in ignore_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def _is_ignored(finding: dict, ignored: set) -> bool:
    fp = finding.get("Fingerprint") or ""
    if fp in ignored:
        return True
    # With absolute scan targets gitleaks prefixes the fingerprint with
    # the target path; the ignore entry is the path-relative form.
    return any(fp.endswith(":" + e) or fp.endswith(e) for e in ignored)


class DogfoodTests(unittest.TestCase):
    """Scan a real tree end-to-end when LEFTBLOCK_DOGFOOD_TREE is set."""

    def test_dogfood_tree_is_clean(self):
        tree = os.environ.get("LEFTBLOCK_DOGFOOD_TREE")
        if not tree:
            self.skipTest("LEFTBLOCK_DOGFOOD_TREE not set")
        if GITLEAKS is None:
            self.skipTest("gitleaks binary not installed")
        tree_path = Path(tree).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            proc = run_gitleaks(tree_path, report)
            ignored = load_ignore_fingerprints(tree_path)
            findings = []
            if proc.returncode == 1 and report.exists():
                data = json.loads(report.read_text())
                findings = [
                    f for f in data if not _is_ignored(f, ignored)
                ]
            self.assertEqual(findings, [], (
                f"dogfood tree {tree} not clean:\n{proc.stdout}\n{proc.stderr}"
            ))


if __name__ == "__main__":
    unittest.main()

def _uuid(rng):
    h = rand_hex(rng, 32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


@unittest.skipUnless(GITLEAKS, "gitleaks not installed")
class KanbusBoardAllowlistTests(unittest.TestCase):
    """Kanbus board data identifiers are not sensitive; nothing else changes.

    Policy (2026-10-20): in board data, actor ids, session UUIDs and UUIDs in
    any field or prose pass. Emails, home paths and keys are still detected
    there, and the same content outside board data is still flagged.
    """

    BOARD_PATHS = (
        "project/issues/PPY-x.json",
        "project/events/2026-10-20T00-00-00.000Z__x.json",
        "project/events/llm_usage.jsonl",
        "project/.cache/index.json",
        "sub/dir/project/issues/PPY-x.json",
        "sub/dir/project/events/e.json",
        "sub/dir/project/.cache/index.json",
    )
    NON_BOARD_PATHS = (
        "notes.md",
        "project/other.json",
        "project/issues/sub/x.json",
        "project/events/sub/x.json",
        "project/events.json",
        "project/issues/x.json.bak",
        "project/issues/x.jsonl",
        "src/project/issues-like/x.json",
        "myproject/issues/x.json",
        "project/.cache/other.json",
        "project/.cache/sub/index.json",
    )

    def setUp(self):
        self.rng = _rng()

    def _content(self):
        """Identifier-bearing content in many shapes (indented and minified)."""
        u = lambda: _uuid(self.rng)  # noqa: E731
        actor_key = "actor" + "_id"
        return {
            "session_fields": json.dumps({
                "session_id": u(), "provider_session_id": u(),
                "resumed_session": u()}, indent=2),
            "prose": json.dumps({
                "description": "session " + u() + " reproduced it",
                "text": "see PPY-" + u() + " and BOTSPY-" + u()}, indent=2),
            "nested_actor": json.dumps(
                {"payload": {actor_key: u()}}, indent=2),
            "split_actor": '"%s"\n:\n"%s"' % (actor_key, u()),
            "minified_event": json.dumps({
                "event_id": u(), actor_key: u(), "session_id": u(),
                "payload": {"comment_id": u(), "text": "x " + u()}}),
        }

    def test_identifiers_pass_in_every_board_path(self):
        for path in self.BOARD_PATHS:
            for shape, doc in self._content().items():
                with self.subTest(path=path, shape=shape):
                    self.assertEqual(scan_and_rule_ids({path: doc}), [])

    def test_session_style_fields_pass_with_any_prefix_in_board_files(self):
        for path in self.BOARD_PATHS:
            for field in ("session_id", "provider_session_id", "resumed_session"):
                for prefix in ("", "PPY-", "BOTSPY-", "kanbus-"):
                    with self.subTest(path=path, field=field, prefix=prefix):
                        doc = json.dumps({field: prefix + _uuid(self.rng)}, indent=2)
                        self.assertEqual(scan_and_rule_ids({path: doc}), [])

    def test_bare_and_prefixed_uuids_in_prose_pass_in_board_files(self):
        for path in self.BOARD_PATHS:
            for field in ("description", "text"):
                for prefix in ("", "PPY-", "kanbus-"):
                    with self.subTest(path=path, field=field, prefix=prefix):
                        doc = json.dumps({
                            "id": "PPY-" + _uuid(self.rng),
                            field: "seen in %s%s today" % (prefix, _uuid(self.rng)),
                        }, indent=2)
                        self.assertEqual(scan_and_rule_ids({path: doc}), [])

    def test_actor_ids_pass_nested_split_and_minified_in_board_files(self):
        key = "actor" + "_id"
        for value in (_uuid(self.rng), "local" + "user"):
            shapes = {
                "root": json.dumps({key: value}, indent=2),
                "nested": json.dumps({"payload": {key: value}}, indent=2),
                "split": '"%s"\n:\n"%s"' % (key, value),
                "minified": json.dumps({"event_type": "x", key: value}),
                "same_line_session": json.dumps(
                    {key: value, "session_id": _uuid(self.rng)}),
            }
            for path in self.BOARD_PATHS:
                for shape, doc in shapes.items():
                    with self.subTest(path=path, shape=shape):
                        self.assertEqual(scan_and_rule_ids({path: doc}), [])

    def test_canonical_crlf_event_and_cache_pass(self):
        iid = "PPY-" + _uuid(self.rng)
        event = json.dumps({
            "event_id": _uuid(self.rng), "actor" + "_id": _uuid(self.rng),
            "issue_id": iid}, indent=2).replace("\n", "\r\n")
        self.assertEqual(scan_and_rule_ids({"project/events/e.json": event}), [])
        cache = json.dumps({
            "file_mtimes": {iid + ".json": 1792500000.25},
            "issues": [{"id": iid, "description": "s " + _uuid(self.rng),
                        "session_id": _uuid(self.rng)}]}, indent=2)
        self.assertEqual(scan_and_rule_ids({"project/.cache/index.json": cache}), [])

    def test_same_identifiers_still_flagged_outside_board_paths(self):
        for path in self.NON_BOARD_PATHS:
            for shape, doc in self._content().items():
                with self.subTest(path=path, shape=shape):
                    findings = scan_and_rule_ids({path: doc})
                    self.assertIn("leftblock-session-uuid", findings)

    def test_actor_ids_still_flagged_outside_board_paths(self):
        key = "actor" + "_id"
        doc = json.dumps({key: "local" + "user"}, indent=2)
        split = '"%s"\n:\n"%s"' % (key, "local" + "user")
        for path in self.NON_BOARD_PATHS:
            for shape, content in (("root", doc), ("split", split)):
                with self.subTest(path=path, shape=shape):
                    self.assertIn("leftblock-actor-id",
                                  scan_and_rule_ids({path: content}))

    def test_personal_email_home_path_and_key_still_flagged_in_board_files(self):
        email = "jane." + "doe@" + "example-corp" + ".co"
        user = "jd" + "oe"
        cases = {
            "leftblock-personal-email": json.dumps(
                {"assignee": email}, indent=2),
            "leftblock-home-path-posix": json.dumps(
                {"description": "see /Users/%s/work" % user}, indent=2),
            "leftblock-openai-key": json.dumps(
                {"text": "key sk-proj-" + rand_openai_like(self.rng, 56)},
                indent=2),
        }
        for path in self.BOARD_PATHS:
            for rule, doc in cases.items():
                with self.subTest(path=path, rule=rule):
                    self.assertIn(rule, scan_and_rule_ids({path: doc}))

    def test_key_in_actor_field_still_flagged_in_board_files(self):
        doc = json.dumps({"actor" + "_id": "sk-proj-" + rand_openai_like(self.rng, 56)},
                         indent=2)
        for path in self.BOARD_PATHS:
            with self.subTest(path=path):
                self.assertIn("leftblock-openai-key", scan_and_rule_ids({path: doc}))


ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
LOWER_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
URLSAFE = ALNUM + "_-"


def rand_from(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


def prefixed_provider_keys(rng):
    """(rule id, key) pairs for every provider with a fixed key prefix."""
    return [
        ("leftblock-openai-key", "sk-admin-" + rand_from(rng, URLSAFE, 156)),
        ("leftblock-groq-key", "gsk_" + rand_from(rng, ALNUM, 52)),
        ("leftblock-xai-key", "xai-" + rand_from(rng, ALNUM, 80)),
        ("leftblock-replicate-key", "r8_" + rand_from(rng, ALNUM, 37)),
        ("leftblock-together-key", "tgp_v1_" + rand_from(rng, URLSAFE, 43)),
        ("leftblock-openrouter-key", "sk-or-v1-" + rand_hex(rng, 64)),
        ("leftblock-fireworks-key", "fw_" + rand_from(rng, ALNUM, 24)),
        ("leftblock-cerebras-key", "csk-" + rand_from(rng, LOWER_ALNUM, 48)),
        ("leftblock-langsmith-key", "lsv2_pt_" + rand_hex(rng, 32) + "_" + rand_hex(rng, 10)),
        ("leftblock-langsmith-key", "lsv2_sk_" + rand_hex(rng, 32) + "_" + rand_hex(rng, 10)),
        ("leftblock-elevenlabs-key", "sk_" + rand_hex(rng, 48)),
        ("leftblock-voyage-key", "pa-" + rand_from(rng, URLSAFE, 43)),
        ("leftblock-pinecone-key", "pcsk_" + rand_from(rng, ALNUM, 6) + "_" + rand_from(rng, ALNUM, 60)),
        ("leftblock-pinecone-key", "pcsk_" + rand_from(rng, ALNUM, 5) + "_" + rand_from(rng, ALNUM, 50)),
    ]


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class AiProviderKeyTests(unittest.TestCase):
    """AI provider keys are detected bare (prefixed) or by named assignment."""

    def test_prefixed_keys_detected_bare(self):
        rng = _rng()
        for rule_id, key in prefixed_provider_keys(rng):
            with self.subTest(rule=rule_id, prefix=key[:6]):
                self.assertIn(rule_id, scan_and_rule_ids({"a.py": 'x = "%s"\n' % key}))
                self.assertIn(rule_id, scan_and_rule_ids({"a.txt": key + "\n"}))

    def test_prefix_less_keys_detected_in_named_assignment(self):
        rng = _rng()
        rule = "leftblock-ai-provider-key-assignment"
        cases = [
            ("MISTRAL_API_KEY", rand_from(rng, ALNUM, 32)),
            ("COHERE_API_KEY", rand_from(rng, ALNUM, 40)),
            ("AZURE_OPENAI_API_KEY", rand_hex(rng, 32)),
            ("AZURE_OPENAI_KEY", rand_hex(rng, 32)),
            ("azureopenai_key", rand_hex(rng, 32)),
            ("DEEPGRAM_API_KEY", rand_hex(rng, 40)),
            ("TOGETHER_API_KEY", rand_hex(rng, 64)),
        ]
        styles = [
            "%s=%s\n",
            "%s: %s\n",
            '%s: "%s"\n',
            "export %s='%s'\n",
            'x = {"%s": "%s"}\n',
            '%s = "%s"\n',
            "'%s' => '%s',\n",
            'os.environ["%s"] = "%s"\n',
        ]
        for name, value in cases:
            for style in styles:
                with self.subTest(name=name, style=style):
                    self.assertIn(rule, scan_and_rule_ids({"f.txt": style % (name, value)}))

    def test_assignment_secret_is_only_the_value(self):
        rng = _rng()
        value = rand_from(rng, ALNUM, 32)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            (target / "f.env").write_text("MISTRAL_API_KEY=%s\n" % value)
            report = Path(tmp) / "r.json"
            run_gitleaks(target, report)
            data = json.loads(report.read_text())
        mine = [f for f in data if f["RuleID"] == "leftblock-ai-provider-key-assignment"]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["Match"], "MISTRAL_API_KEY=REDACTED")

    def test_bare_prefix_less_keys_not_detected(self):
        rng = _rng()
        self.assertEqual(scan_and_rule_ids({"f.txt": 'x = "%s"\n' % rand_from(rng, ALNUM, 32)}), [])


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class AiProviderKeyNegativeTests(unittest.TestCase):
    """Hashes, identifiers, references and placeholders must not be flagged."""

    def assert_clean(self, text):
        self.assertEqual(scan_and_rule_ids({"f.txt": text}), [], text)

    def test_hashes_and_uuids(self):
        rng = _rng()
        sha1, sha256 = rand_hex(rng, 40), rand_hex(rng, 64)
        uuid = "-".join(rand_hex(rng, n) for n in (8, 4, 4, 4, 12))
        for text in [sha1, sha256, 'sha = "%s"' % sha1, 'sha = "%s"' % sha256,
                     'digest: "%s"' % sha256, "commit %s" % sha1]:
            with self.subTest(text=text[:12]):
                self.assert_clean(text + "\n")
        # UUIDs are the session-uuid rule's business, never an AI key rule.
        found = scan_and_rule_ids({"f.txt": 'id = "%s"\n' % uuid})
        self.assertEqual([r for r in found if r != "leftblock-session-uuid"], [])

    def test_prefix_lookalikes_in_ordinary_text(self):
        rng = _rng()
        texts = [
            "pip install sk-learn scikit-learn",
            "book the spa-resort and npa-123 today",
            "fw_" + rand_from(rng, ALNUM, 10),
            "csk-" + rand_from(rng, LOWER_ALNUM, 10),
            "gsk_" + rand_from(rng, ALNUM, 10),
            "pa-" + rand_from(rng, URLSAFE, 12),
            "sk_" + rand_hex(rng, 12),
            "my_fw_" + rand_from(rng, ALNUM, 24),
            "spa-" + rand_from(rng, URLSAFE, 43),
            "pa-" + rand_from(rng, URLSAFE, 60),
            "fw_" + rand_from(rng, ALNUM, 40),
            "sk_" + rand_hex(rng, 64),
        ]
        for text in texts:
            with self.subTest(text=text[:20]):
                self.assert_clean(text + "\n")

    def test_references_and_placeholders(self):
        texts = [
            "OPENAI_API_KEY=${OPENAI_API_KEY}",
            'os.environ["OPENAI_API_KEY"]',
            'key = os.environ.get("OPENAI_API_KEY")',
            "MISTRAL_API_KEY=your-key-here",
            "MISTRAL_API_KEY=<your-api-key>",
            'COHERE_API_KEY: "<your-api-key>"',
            "AZURE_OPENAI_API_KEY=changeme",
            "DEEPGRAM_API_KEY=$DEEPGRAM_API_KEY",
            "TOGETHER_API_KEY=your_together_api_key_goes_here",
            "GROQ_API_KEY=YOUR_GROQ_API_KEY_HERE_PLEASE",
            "api_key_name = some-long-descriptive-variable-name",
        ]
        for text in texts:
            with self.subTest(text=text):
                self.assert_clean(text + "\n")
