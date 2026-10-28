"""Recorded, per-finding overrides kept in a committed .leftblock-allow.yml.

An override approves one finding: one rule on one exact line content in one
file. The id is a hash of that triple, so changing the line re-blocks it. The
allow file is read from the Git index, so only a staged override counts and it
always appears in the commit and its review.
"""

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone

import yaml

ALLOW_FILE = ".leftblock-allow.yml"
MIN_REASON = 10
ALLOW_HEADER = (
    "# LeftBlock overrides: each entry approves one finding (one rule on one exact\n"
    "# line content in one file). Changing that line re-blocks it. `kind` is the\n"
    "# rule's category, shown for reviewers; it is not part of matching.\n"
)


class AllowError(Exception):
    pass


def _git_bytes(repo_root, *args):
    return subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, check=False,
        stdin=subprocess.DEVNULL,
    )


def finding_id(repo_root, rule, file, start, end):
    """Hash of rule, file and the staged line content, or None if unreadable."""
    if not isinstance(rule, str) or not isinstance(file, str):
        return None
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        return None
    proc = _git_bytes(repo_root, "show", ":" + file)
    if proc.returncode:
        return None
    lines = proc.stdout.decode("utf-8", errors="replace").split("\n")
    if end > len(lines):
        return None
    return content_id(rule, file, "\n".join(lines[start - 1:end]))


def content_id(rule, file, content):
    """The id of one rule on one exact line content in one file."""
    digest = hashlib.sha256(f"{rule}\0{file}\0{content}".encode("utf-8"))
    return digest.hexdigest()[:16]


def attach_ids(repo_root, results):
    """Replace StartLine/EndLine on findings with `line` and an id (when computable)."""
    for result in results:
        if result.error or not isinstance(result.findings, list):
            continue
        for finding in result.findings:
            start, end = finding.pop("StartLine", None), finding.pop("EndLine", None)
            if type(start) is int and start >= 1:
                finding["line"] = start
            if finding.get("File") == ALLOW_FILE:
                continue  # the allow file can never approve itself
            ident = finding_id(
                repo_root, finding.get("RuleID"), finding.get("File"), start, end,
            )
            if ident:
                finding["id"] = ident


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
    allowed = []
    for result in results:
        if result.error or result.clean or not isinstance(result.findings, list):
            continue
        remaining = []
        for finding in result.findings:
            key = (finding.get("id"), finding.get("RuleID"), finding.get("File"))
            if key[0] and key in index:
                allowed.append((finding, index[key]))
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
