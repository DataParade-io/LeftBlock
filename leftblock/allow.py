"""Recorded, per-finding overrides kept in a committed .leftblock-allow.yml.

An override approves one reviewed value: one rule matching one exact value in
one file. The id is a hash of the rule, the file and the matched text, so
changing the matched value re-blocks it, while unrelated edits to the rest of
the line do not. The same value flagged by the same rule on several lines of a
file is one reviewed value, so one override covers all of them. Entries
recorded by earlier versions hash the whole line instead; those are still
honoured. The allow file is read from the Git index, so only a staged override counts and it
always appears in the commit and its review.
"""

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone

import yaml

from leftblock import bypass

ALLOW_FILE = ".leftblock-allow.yml"
MIN_REASON = 10
ALLOW_HEADER = (
    "# LeftBlock overrides: each entry approves one reviewed value (one rule\n"
    "# matching one exact value in one file). Changing the matched value re-blocks\n"
    "# it; unrelated edits to the line do not. `kind` is the rule's category,\n"
    "# shown for reviewers; it is not part of matching.\n"
)


class AllowError(Exception):
    pass


def _git_bytes(repo_root, *args):
    return subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, check=False,
        stdin=subprocess.DEVNULL,
    )


class StagedFiles:
    """Staged file contents read once per file, split into lines (as bytes)."""

    def __init__(self, repo_root):
        self.repo_root = repo_root
        self._lines = {}
        self._starts = None

    def lines(self, file):
        if file not in self._lines:
            proc = _git_bytes(self.repo_root, "show", ":" + file)
            self._lines[file] = None if proc.returncode else proc.stdout.split(b"\n")
        return self._lines[file]

    def line_range(self, finding):
        """(lines, start, end) for a finding's line range, or None if unreadable."""
        file, start, end = finding.get("File"), finding.get("StartLine"), finding.get("EndLine")
        if not isinstance(finding.get("RuleID"), str) or not isinstance(file, str):
            return None
        if type(start) is not int or type(end) is not int or start < 1 or end < start:
            return None
        lines = self.lines(file)
        if lines is None or end > len(lines):
            return None
        return lines, start, end

    def _hunk_starts(self):
        """{(file, line)} for the first added line of each hunk in the staged diff; None if unreadable."""
        if self._starts is None:
            proc = _git_bytes(
                self.repo_root, "-c", "core.quotePath=false", "diff", "--cached", "-U0",
                "--no-color", "--no-ext-diff", "--no-renames", "--text",
            )
            if proc.returncode:
                self._starts = False
            else:
                added = {(path, number) for path, number, _ in bypass._added_lines(proc.stdout)}
                self._starts = {(p, n) for p, n in added if (p, n - 1) not in added}
        return self._starts or None

    def _slice(self, finding, shift):
        found = self.line_range(finding)
        first, last = finding.get("StartColumn"), finding.get("EndColumn")
        if not found or found[1] != found[2] or type(first) is not int or type(last) is not int:
            return None
        first, last = first - shift, last - shift
        if first < 1 or last < first:
            return None
        text = found[0][found[1] - 1][first - 1:last].decode("utf-8", errors="replace").strip()
        return text or None

    def match_candidates(self, finding):
        """Possible matched texts for a finding, most likely first (at most two)."""
        # Gitleaks scans each hunk of the staged diff as one text and counts a
        # line's columns from the newline before it, so every line but the
        # first of a hunk is reported one column too far right.
        starts = self._hunk_starts()
        first = 0 if starts and (finding.get("File"), finding.get("StartLine")) in starts else 1
        texts = [self._slice(finding, first), self._slice(finding, 1 - first)]
        return [t for i, t in enumerate(texts) if t and t not in texts[:i]]

    def match_text(self, finding):
        """The matched text, sliced from the staged line by gitleaks' columns.

        The check runs gitleaks with --redact, so its own Secret and Match are
        masked. Columns are 1-based byte offsets and EndColumn is inclusive.
        Only single-line matches are sliced; None when unreadable or empty or
        when the staged diff cannot place the line.
        """
        if self._hunk_starts() is None:
            return None
        texts = self.match_candidates(finding)
        return texts[0] if texts else None

    def ids(self, finding):
        """(match id, legacy line id); either may be None if it cannot be computed."""
        found = self.line_range(finding)
        if not found:
            return None, None
        rule, file = finding["RuleID"], finding["File"]
        lines, start, end = found
        whole = b"\n".join(lines[start - 1:end]).decode("utf-8", errors="replace")
        text = self.match_text(finding)
        return (content_id(rule, file, text) if text else None), content_id(rule, file, whole)


def content_id(rule, file, content):
    """The id of one rule on one file and one piece of content.

    Findings use the matched text as content (the legacy ids used the whole line).
    """
    digest = hashlib.sha256(f"{rule}\0{file}\0{content}".encode("utf-8"))
    return digest.hexdigest()[:16]


def attach_ids(repo_root, results):
    """Replace position fields on findings with `line`, an `id` and a `legacy_id`.

    `id` hashes the rule, the file and the matched text, so unrelated edits to
    the line do not change it. `legacy_id` is the older whole-line hash, still
    accepted by `apply_allowlist`. When the matched text cannot be read, `id` is
    the line hash, so the finding can still be overridden.
    """
    staged = StagedFiles(repo_root)
    for result in results:
        if result.error or not isinstance(result.findings, list):
            continue
        for finding in result.findings:
            start = finding.get("StartLine")
            if type(start) is int and start >= 1:
                finding["line"] = start
            if finding.get("File") != ALLOW_FILE:  # the allow file can never approve itself
                match, legacy = staged.ids(finding)
                if match or legacy:
                    finding["id"] = match or legacy
                    finding["legacy_id"] = legacy
            for key in ("StartLine", "EndLine", "StartColumn", "EndColumn"):
                finding.pop(key, None)


def parse_allowlist(text):
    """Return entries from allow-file text; raise AllowError if invalid."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        raise AllowError("invalid YAML")
    if not isinstance(data, dict) or data.get("version") != 1 or type(data.get("version")) is not int:
        raise AllowError("unsupported version")
    entries = data.get("allow")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise AllowError("allow must be a list")
    for entry in entries:
        if not isinstance(entry, dict):
            raise AllowError("invalid entry")
        for key in ("id", "rule", "file"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise AllowError("entry missing " + key)
        if not isinstance(entry.get("reason"), str) or len(entry["reason"].strip()) < MIN_REASON:
            raise AllowError("entry reason too short")
    return entries


def load_allowlist(repo_root):
    """Entries from the staged allow file; [] when it is not in the index."""
    staged = _git_bytes(repo_root, "ls-files", "--stage", "--", ALLOW_FILE)
    if staged.returncode:
        raise AllowError("cannot read index")
    if not staged.stdout.strip():
        return []
    proc = _git_bytes(repo_root, "show", ":" + ALLOW_FILE)
    if proc.returncode:
        raise AllowError("cannot read staged file")
    try:
        return parse_allowlist(proc.stdout.decode("utf-8"))
    except UnicodeDecodeError:
        raise AllowError("not UTF-8")


def apply_allowlist(results, entries):
    """Move allowed findings out of the results; return [(finding, reason)]."""
    index = {
        (e["id"], e["rule"], e["file"]): " ".join(e["reason"].split()) for e in entries
    }
    # Entries recorded before match-based ids hash the whole line; they still apply.
    allowed = []
    for result in results:
        if result.error or result.clean or not isinstance(result.findings, list):
            continue
        remaining = []
        for finding in result.findings:
            rule, file = finding.get("RuleID"), finding.get("File")
            hit = next((i for i in (finding.get("id"), finding.get("legacy_id"))
                        if i and (i, rule, file) in index), None)
            if hit:
                # Report the id of the entry that applied, as it appears in the allow file.
                allowed.append((dict(finding, id=hit), index[(hit, rule, file)]))
            else:
                remaining.append(finding)
        if remaining:
            result.findings = remaining
        else:
            result.clean, result.findings = True, None
    return allowed


def _quote(value):
    # JSON strings are valid YAML double-quoted scalars.
    return json.dumps(value, ensure_ascii=False)


def _render(entries):
    out = [ALLOW_HEADER + "version: 1\n"]
    if not entries:
        return out[0] + "allow: []\n"
    out.append("allow:\n")
    for e in entries:
        added = str(e.get("added", ""))
        out.append(f"  - id: {_quote(e['id'])}\n")
        out.append(f"    rule: {_quote(e['rule'])}\n")
        out.append(f"    file: {_quote(e['file'])}\n")
        if e.get("kind"):
            out.append(f"    kind: {_quote(e['kind'])}\n")
        out.append(f"    reason: {_quote(' '.join(e['reason'].split()))}\n")
        if added:
            plain = re.fullmatch(r"\d{4}-\d{2}-\d{2}", added)
            out.append("    added: " + (added if plain else _quote(added)) + "\n")
    return "".join(out)


def record_overrides(repo_root, findings, reason):
    """Append entries for findings (dicts with id/RuleID/File, optional kind) to the allow file.

    Returns the findings newly recorded. The working-tree file must be valid.
    """
    path = os.path.join(repo_root, ALLOW_FILE)
    entries = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            entries = parse_allowlist(f.read())
    known = {e["id"] for e in entries}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    added = []
    for finding in findings:
        if finding["id"] in known:
            continue
        known.add(finding["id"])
        entry = {
            "id": finding["id"], "rule": finding["RuleID"], "file": finding["File"],
            "reason": reason, "added": today,
        }
        if finding.get("kind"):
            entry["kind"] = finding["kind"]  # informational, for reviewers only
        entries.append(entry)
        added.append(finding)
    with open(path, "w", encoding="utf-8") as f:
        f.write(_render(entries))
    return added


def snapshot(repo_root):
    """Working-tree bytes (or None) and the index entry (or None) of the file."""
    path = os.path.join(repo_root, ALLOW_FILE)
    content = None
    if os.path.exists(path):
        with open(path, "rb") as f:
            content = f.read()
    staged = _git_bytes(repo_root, "ls-files", "--stage", "--", ALLOW_FILE)
    entry = None
    if staged.returncode == 0 and staged.stdout.strip():
        meta = staged.stdout.decode().split("\t")[0].split()
        entry = (meta[0], meta[1])
    return content, entry


def restore(repo_root, snap):
    """Put the allow file and its index entry back exactly as snapshotted."""
    content, entry = snap
    path = os.path.join(repo_root, ALLOW_FILE)
    if content is None:
        if os.path.exists(path):
            os.remove(path)
    else:
        with open(path, "wb") as f:
            f.write(content)
    if entry is None:
        _git_bytes(repo_root, "rm", "--cached", "-q", "--ignore-unmatch", "--", ALLOW_FILE)
    else:
        _git_bytes(repo_root, "update-index", "--add", "--cacheinfo", f"{entry[0]},{entry[1]},{ALLOW_FILE}")
