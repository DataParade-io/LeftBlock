"""Running the detectors.

Every detector reduces to the set of ``(file, line)`` pairs it flagged, plus a
count of findings by rule. Gitleaks runs through ``gitleaks dir``; the deep
scan runs LeftBlock's own ``deep.scan`` (default labels, threshold and
exclusions) on the lines handed to it. Reports are written with ``--redact``
to a scratch file that is read and deleted; no value is ever kept.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter

from leftblock import deep

STOCK = "gitleaks-stock"
LEFTBLOCK = "gitleaks-leftblock"
DEEP = "deep-scan"
COMBINED = "leftblock+deep"
ALL = (STOCK, LEFTBLOCK, DEEP, COMBINED)

SHIPPED_CONFIG = os.path.join(os.path.dirname(deep.__file__), "data", "gitleaks.toml")
KANBUS_DATA = re.compile(r"(^|/)project/(issues|events)/[^/]+\.jsonl?$")  # same pattern as cli.KANBUS_DATA


class Flags:
    """What one detector flagged: lines, and findings per rule."""

    def __init__(self):
        self.lines = set()
        self.by_rule = Counter()
        self.findings = 0
        self.items = []  # (file, start, end) of every finding
        self.line_rules = {}  # (file, line) -> rule ids that flagged it
        self.seconds = 0.0

    def add(self, file, start, end, rule):
        self.findings += 1
        self.items.append((file, start, end))
        self.by_rule[rule] += 1
        for line in range(start, end + 1):
            self.lines.add((file, line))
            self.line_rules.setdefault((file, line), set()).add(rule)

    def union(self, other):
        merged = Flags()
        merged.lines = self.lines | other.lines
        merged.by_rule = self.by_rule + other.by_rule
        merged.findings = self.findings + other.findings
        merged.items = self.items + other.items
        merged.line_rules = {k: set(v) for k, v in self.line_rules.items()}
        for key, rules in other.line_rules.items():
            merged.line_rules.setdefault(key, set()).update(rules)
        merged.seconds = self.seconds + other.seconds
        return merged


def gitleaks_binary():
    found = shutil.which("gitleaks")
    if not found:
        raise RuntimeError("gitleaks is not on PATH (CI pins 8.30.1).")
    return found


def gitleaks_version():
    out = subprocess.run([gitleaks_binary(), "version"], capture_output=True, text=True).stdout
    return out.strip()


def run_gitleaks(root, config=None, prefix=""):
    """Scan the tree under ``root`` with ``gitleaks dir``; return Flags whose file ids are ``prefix`` + the path under ``root``."""
    flags = Flags()
    started = time.time()
    fd, report = tempfile.mkstemp(prefix="gitleaks-report-", suffix=".json")
    os.close(fd)
    try:
        command = [
            gitleaks_binary(), "dir", root, "--no-banner", "--redact", "--exit-code", "0",
            "--log-level", "error", "--report-format", "json", "--report-path", report,
        ]
        if config:
            command += ["--config", config]
        proc = subprocess.run(command, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if proc.returncode:
            raise RuntimeError("gitleaks failed (exit %d)" % proc.returncode)
        with open(report, encoding="utf-8") as handle:
            findings = json.load(handle) or []
    finally:
        os.unlink(report)
    base = os.path.realpath(root).rstrip("/") + "/"
    for item in findings:
        path = os.path.realpath(item["File"]) if os.path.isabs(item["File"]) else item["File"]
        if path.startswith(base):
            path = path[len(base):]
        flags.add(prefix + path, int(item["StartLine"]), int(item["EndLine"]), item["RuleID"])
    flags.seconds = time.time() - started
    return flags


def run_deep(additions, cache_path=None, log=None, shard=None):
    """Run LeftBlock's deep scan over ``additions`` ``[(file, line, bytes)]``.

    Results are cached per file in ``cache_path`` (JSON lines of
    ``{"file", "findings": [[line, rule], ...]}``) so an interrupted run
    resumes where it stopped. The cache name carries a digest of the lines, so
    it is only reused for exactly the same lines.

    ``shard=(k, n)`` scans only every n-th file (starting at k), appending to a
    shard-specific cache file and returning no findings. The model leaves most
    of a multi-core CPU idle, so several shard processes run in parallel and a
    final unsharded run reads all the caches and scores them.

    Returns (Flags, bytes of text the model reads).
    """
    detector = deep.load_detector(log)
    if cache_path:
        # The cache is only valid for exactly these lines.
        digest = hashlib.sha1()
        for file, line, text in additions:
            digest.update(("%s\0%d\0" % (file, line)).encode() + text + b"\0")
        cache_path = cache_path.replace(".jsonl", "-%s.jsonl" % digest.hexdigest()[:12])
    by_file = {}
    for file, line, text in additions:
        by_file.setdefault(file, []).append((file, line, text))
    done = {}
    own = cache_path
    if cache_path:
        stem = cache_path[:-len(".jsonl")]
        for path in sorted(glob.glob(glob.escape(stem) + "*.jsonl")):
            with open(path, encoding="utf-8") as handle:
                for record in map(json.loads, filter(None, map(str.strip, handle))):
                    done[record["file"]] = record["findings"]
        if shard:
            own = "%s-shard%d.jsonl" % (stem, shard[0])
    flags = Flags()
    total_bytes = sum(len(t) + 1 for _, _, t in additions)
    started, seen = time.time(), 0
    out = open(own, "a", encoding="utf-8") if own else None
    try:
        for index, (file, items) in enumerate(sorted(by_file.items())):
            size = sum(len(t) + 1 for _, _, t in items)
            if shard and file not in done and index % shard[1] != shard[0]:
                continue
            if file not in done:
                found = deep.scan(items, detector, deep.DEFAULT_LABELS, deep.DEFAULT_THRESHOLD, KANBUS_DATA)
                done[file] = [[f["line"], f["RuleID"]] for f in found]
                if out:
                    out.write(json.dumps({"file": file, "findings": done[file]}) + "\n")
                    out.flush()
            seen += size
            if shard:
                if log:
                    log("deep scan shard %d/%d: file %d/%d, %.0f KB scanned, %.0f s" % (shard[0], shard[1], index + 1, len(by_file), seen / 1024, time.time() - started))
                continue
            # deep.scan reports one finding per distinct (rule, file, line text); a
            # line repeated verbatim elsewhere in the window set is the same finding.
            same = {}
            for _, number, text in items:
                same.setdefault(text, []).append(number)
            text_of = {number: text for _, number, text in items}
            for line, rule in done[file]:
                for number in same.get(text_of.get(line), [line]):
                    flags.add(file, number, number, rule)
            if log and (index % 25 == 0):
                elapsed = time.time() - started
                log("deep scan: %d/%d files, %.0f/%.0f KB, %.0f s" % (index + 1, len(by_file), seen / 1024, total_bytes / 1024, elapsed))
    finally:
        if out:
            out.close()
    flags.seconds = time.time() - started
    return flags, total_bytes
