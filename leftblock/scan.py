"""Scan text that is not in git: JSONL records on stdin, or files and directories.

`leftblock scan` gives other tools the same rules the commit hook uses: the
shipped gitleaks ruleset, run with --redact, and the same post-filters (the WIF
base58check check). Optionally `--deep` adds the Privacy Filter model with the
deep scan's defaults. Recorded overrides (.leftblock-allow.yml) are a
property of a repository's commits and are never applied here.

Records are written one file each into a private temporary directory so that
gitleaks runs once over all of them. Gitleaks reports line and column
positions; they are converted to UTF-8 byte offsets in the original text.
Matched values are used only to validate and to compute finding ids, and are
never returned or printed.
"""

import bisect
import itertools
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from leftblock import allow as allowlist
from leftblock import deep
from leftblock import validators

RULESET = Path(__file__).resolve().parent / "data" / "gitleaks.toml"

PERSONAL_RULES = frozenset((
    "leftblock-personal-email", "leftblock-home-path-posix", "leftblock-home-path-windows",
    "leftblock-session-uuid", "leftblock-actor-id",
))
CRYPTO_RULES = frozenset((
    "leftblock-eth-private-key", "leftblock-wif-key", "leftblock-bip39-mnemonic",
))

# Gitleaks counts the columns of every line after the first of a scanned text
# from the newline before it, so they come out one too far right. The commit
# hook meets this in the staged diff (see allow.StagedFiles); the same happens
# for a whole file in `gitleaks dir`.
LATER_LINE_SHIFT = 1

BINARY_PROBE = 8000
SURROGATE = re.compile("[\ud800-\udfff]")
RECORD_FILE = re.compile(r"(\d+)\.txt")


class ScanError(Exception):
    """Anything that stops a scan; the message is one line and holds no matched value."""


def kind_of(rule):
    """The category of a rule: secret, personal, crypto or deep."""
    if rule.startswith(deep.RULE_PREFIX):
        return "deep"
    if rule in PERSONAL_RULES:
        return "personal"
    if rule in CRYPTO_RULES:
        return "crypto"
    return "secret"


# --- Positions -------------------------------------------------------------------

class LineIndex:
    """Byte offset of the start of each line of some bytes."""

    def __init__(self, data):
        self.size = len(data)
        self.starts = [0]
        at = data.find(b"\n")
        while at != -1:
            self.starts.append(at + 1)
            at = data.find(b"\n", at + 1)

    def line_of(self, offset):
        """The 1-based line holding byte `offset`."""
        return bisect.bisect_right(self.starts, offset)

    def span(self, start_line, start_column, end_line, end_column):
        """(start, end) byte offsets from gitleaks' 1-based line and column positions.

        Columns are byte columns, EndColumn is inclusive, and later lines are
        shifted (LATER_LINE_SHIFT). End is exclusive. None when the position is
        not inside the text.
        """
        if not (1 <= start_line <= end_line <= len(self.starts)) or start_column < 1 or end_column < 1:
            return None
        start = self.starts[start_line - 1] + start_column - 1 - (LATER_LINE_SHIFT if start_line > 1 else 0)
        end = self.starts[end_line - 1] + end_column - (LATER_LINE_SHIFT if end_line > 1 else 0)
        if not 0 <= start < end <= self.size:
            return None
        return start, end


def byte_span(data, start_line, start_column, end_line, end_column):
    """LineIndex(data).span(...), for callers that convert one position."""
    return LineIndex(data).span(start_line, start_column, end_line, end_column)


def char_to_byte_offsets(text, errors="surrogatepass"):
    """Byte offset of each character of `text` (and one past the last), as UTF-8."""
    offsets = [0]
    offsets.extend(itertools.accumulate(len(c.encode("utf-8", errors)) for c in text))
    return offsets


def encode(text):
    """The UTF-8 bytes of record text; lone surrogates are kept as three bytes each."""
    return text.encode("utf-8", "surrogatepass")


# --- Gitleaks --------------------------------------------------------------------

@contextmanager
def private_tempdir():
    """A temporary directory only this user can enter, removed on any exit."""
    path = tempfile.mkdtemp(prefix="leftblock-scan-")
    try:
        if os.name == "posix":
            os.chmod(path, 0o700)
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _gitleaks_binary():
    binary = shutil.which("gitleaks")
    if not binary:
        raise ScanError("Gitleaks is required: install it and put it on PATH.")
    return binary


def run_gitleaks(target, workdir, number=0):
    """Findings (report dicts) for a file or directory; values never reach the report.

    `--exit-code 0` makes any nonzero status a real failure. The ignore path is
    an empty directory, so a .gitleaksignore next to the data does not silence
    anything, and inline allow comments are scanned like everything else.
    """
    binary = _gitleaks_binary()
    report = os.path.join(workdir, "report-%d.json" % number)
    nothing = os.path.join(workdir, "no-ignore")
    os.makedirs(nothing, exist_ok=True)
    if target.startswith("-"):
        target = "./" + target
    argv = [
        binary, "dir", target, "--config", str(RULESET), "--redact", "--no-banner",
        "--ignore-gitleaks-allow", "--gitleaks-ignore-path", nothing,
        "--report-format", "json", "--report-path", report,
        "--exit-code", "0", "--log-level", "error",
    ]
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, check=False,
        )
    except OSError:
        raise ScanError("Gitleaks could not run; check its installation.")
    if proc.returncode:
        raise ScanError("Gitleaks failed (exit status %d)." % proc.returncode)
    try:
        with open(report, "r", encoding="utf-8") as handle:
            items = json.load(handle)
    except (OSError, ValueError):
        raise ScanError("Gitleaks report unavailable or invalid.")
    if not isinstance(items, list) or any(not isinstance(i, dict) for i in items):
        raise ScanError("Gitleaks report unavailable or invalid.")
    return items


def _report_fields(item):
    rule, name = item.get("RuleID"), item.get("File")
    numbers = [item.get(k) for k in ("StartLine", "StartColumn", "EndLine", "EndColumn")]
    if not isinstance(rule, str) or not isinstance(name, str) or any(type(n) is not int for n in numbers):
        raise ScanError("Gitleaks report unavailable or invalid.")
    return rule, name, numbers


def make_finding(name, rule, data, index, start, end, score=None):
    """The output dict for one span of `data`; None when a validator rejects the match."""
    value = data[start:end].decode("utf-8", errors="replace").strip()
    if not validators.passes(rule, value):
        return None
    finding = {
        "file": name, "line": index.line_of(start), "start": start, "end": end, "rule": rule,
        "kind": kind_of(rule), "finding_id": allowlist.content_id(rule, name, value),
    }
    if score is not None:
        finding["score"] = score
    return finding


def gitleaks_findings(items, resolve):
    """[(source, finding)] from a gitleaks report.

    `resolve(file)` returns (source, name, data) for a scanned file: an opaque
    key for the caller, the name findings carry, and the scanned bytes.
    """
    found, indexes = [], {}
    for item in items:
        rule, file, (sl, sc, el, ec) = _report_fields(item)
        source, name, data = resolve(file)
        if file not in indexes:
            indexes[file] = LineIndex(data)
        span = indexes[file].span(sl, sc, el, ec)
        if span is None:
            raise ScanError("Could not place a finding in its text; scan aborted.")
        finding = make_finding(name, rule, data, indexes[file], span[0], span[1])
        if finding:
            found.append((source, finding))
    return found


def deep_findings(name, data, text, detector, labels, threshold, index, errors):
    """Deep-scan findings for `text`, whose bytes are `data`; spans are converted to byte offsets.

    Bytes that are not UTF-8 reach `text` as lone surrogates; the model reads
    them as U+FFFD, which keeps every character offset.
    """
    spans = deep.scan_text(SURROGATE.sub("\ufffd", text), detector, labels, threshold)
    if not spans:
        return []
    offsets = char_to_byte_offsets(text, errors)
    found = [
        make_finding(name, deep.RULE_PREFIX + label, data, index, offsets[first], offsets[last], score)
        for first, last, label, score in spans
    ]
    return [f for f in found if f]


# --- JSONL records -----------------------------------------------------------------

def read_records(lines):
    """[(id, text)] from JSONL lines (bytes); blank lines are skipped."""
    records = []
    for number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError):
            raise ScanError("Line %d is not valid JSON." % number)
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str) or not isinstance(obj.get("text"), str):
            raise ScanError('Line %d must be an object with string "id" and "text" fields.' % number)
        records.append((obj["id"], obj["text"]))
    return records


def _order(finding):
    return (finding["start"], finding["end"], finding["rule"])


def scan_records(records, detector_factory=None, labels=None, threshold=None):
    """Findings for [(id, text)], each with the record id as "file", in record order.

    One gitleaks run covers every record. `detector_factory`, when given, loads
    the deep-scan detector (only if there is something to scan).
    """
    if not records:
        return []
    detector = detector_factory() if detector_factory else None
    with private_tempdir() as workdir:
        folder = os.path.join(workdir, "records")
        os.mkdir(folder)
        for number, (_, text) in enumerate(records):
            with open(os.path.join(folder, "%d.txt" % number), "wb") as handle:
                handle.write(encode(text))
        items = run_gitleaks(folder, workdir)

    def resolve(file):
        match = RECORD_FILE.fullmatch(os.path.basename(file))
        if not match or os.path.normpath(os.path.dirname(file)) != os.path.normpath(folder) \
                or int(match.group(1)) >= len(records):
            raise ScanError("Gitleaks reported a source that was not scanned.")
        number = int(match.group(1))
        return number, records[number][0], encode(records[number][1])

    # The temporary copies are gone; the texts are still in memory.
    by_record = {}
    for number, finding in gitleaks_findings(items, resolve):
        by_record.setdefault(number, []).append(finding)
    if detector:
        for number, (record_id, text) in enumerate(records):
            data = encode(text)
            by_record.setdefault(number, []).extend(deep_findings(
                record_id, data, text, detector, labels, threshold, LineIndex(data), "surrogatepass",
            ))
    return [f for number in sorted(by_record) for f in sorted(by_record[number], key=_order)]


# --- Paths -----------------------------------------------------------------------------

def walk(paths):
    """Every regular file under the paths (files as given, directories recursively), in order."""
    files = []
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d != ".git")
                files.extend(os.path.join(root, n) for n in sorted(names) if os.path.isfile(os.path.join(root, n)))
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise ScanError("No such file or directory: %s" % json.dumps(path, ensure_ascii=True))
    return files


def scan_paths(paths, detector_factory=None, labels=None, threshold=None, kanbus_data=None):
    """Findings for files and directories, with `file` the path and `line` the line."""
    files = walk(paths)
    with private_tempdir() as workdir:
        items = []
        for number, path in enumerate(paths):
            items.extend(run_gitleaks(path, workdir, number))
    cache = {}

    def data_for(file):
        if file not in cache:
            try:
                with open(file, "rb") as handle:
                    cache[file] = handle.read()
            except OSError:
                raise ScanError("Could not read a scanned file.")
        return cache[file]

    found = [f for _, f in gitleaks_findings(items, lambda file: (file, file, data_for(file)))]
    if detector_factory and files:
        detector = detector_factory()
        for path in files:
            if deep.skip_file(path, kanbus_data):
                continue
            data = data_for(path)
            if b"\0" in data[:BINARY_PROBE]:
                continue
            found.extend(deep_findings(
                path, data, data.decode("utf-8", errors="surrogateescape"), detector, labels,
                threshold, LineIndex(data), "surrogateescape",
            ))
    unique = {(f["file"], f["start"], f["end"], f["rule"]): f for f in found}
    return sorted(unique.values(), key=lambda f: (f["file"],) + _order(f))
