"""Opt-in model-based deep scan.

`leftblock deep-scan` reads the added lines of the staged diff (or of a commit
range) with OpenAI's Privacy Filter, a token-classification model, and reports
the spans it labels as sensitive. It is slow and heavy compared with the
gitleaks gate, so it is never part of the commit hook.

This module is pure: it knows nothing about command-line output. The detector
is a callable `detect(text) -> [(start, end, label, score), ...]` so tests can
swap the model for a stub (see DETECTOR_ENV). The matched value is used only
to filter false positives and is never returned, logged or printed.
"""

import bisect
import importlib
import importlib.util
import os
import re
import subprocess

from leftblock import allow as allowlist
from leftblock import bypass

MODEL = "openai/privacy-filter"
RULE_PREFIX = "privacy-filter-"
INSTALL_HINT = "pip install 'leftblock[deep]'"

# Defaults come from a local evaluation over five repositories.
DEFAULT_LABELS = ("secret", "private_email", "private_phone", "private_address")
OPTIONAL_LABELS = ("private_person", "account_number", "private_date", "private_url")
ALL_LABELS = DEFAULT_LABELS + OPTIONAL_LABELS
DEFAULT_THRESHOLD = 0.9

# Test seam: "module:factory" names an importable zero-argument callable that
# returns a detector. Only the specs set it; it replaces the real model.
DETECTOR_ENV = "LEFTBLOCK_DEEP_DETECTOR"

# Text sent to the model per call, in characters (CPU time grows faster than linearly past ~2000). Longer lines are windowed.
CHUNK_CHARS = 2000


class DeepScanError(Exception):
    pass


class ExtraMissing(DeepScanError):
    pass


# --- Exclusions ---------------------------------------------------------------

# Generated, minified, vendored and lock files, plus the compiled-bytecode
# paths the shipped gitleaks ruleset already skips, Kanbus's cache and the
# allow file (its reasons are prose, not source).
SKIP_PATHS = [re.compile(p) for p in (
    r"(^|/)__pycache__/",
    r"\.pyc$",
    r"(^|/)project/\.cache/",
    r"(^|/)(node_modules|vendor|vendored|third_party|site-packages|dist)/",
    r"\.min\.(js|mjs|css)$",
    r"\.(map|snap|lock|lockb)$",
    r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|go\.sum|bun\.lock)$",
    r"(^|/)[^/]*\.generated\.[^/]+$",
    r"_pb2(_grpc)?\.py$|\.pb\.go$",
    r"(^|/)" + re.escape(allowlist.ALLOW_FILE) + r"$",
)]

SKIP_LINE = re.compile(r"placeholder|example|fake|synthetic|dummy", re.IGNORECASE)

# Identifier shapes the model keeps calling secrets: not worth a block.
SECRET_SHAPES = [re.compile(p) for p in (
    # UUID
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    # hex hash or digest
    r"[0-9a-fA-F]{7,}",
    # hex colour
    r"#?(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})",
    # ISO date or timestamp
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?",
    # prefixed issue id, such as ABC-123 or kanbus-1f1489
    r"[A-Za-z][A-Za-z0-9]{1,15}-[0-9a-fA-F]{3,12}",
)]

# The shipped ruleset's personal-email allowlist (leftblock/data/gitleaks.toml),
# plus .internal. tests/test_deep_scan.py keeps the two in step.
EMAIL_ALLOW = [re.compile(p) for p in (
    r"@users\.noreply\.github\.com",
    r"(^|[^a-zA-Z0-9._%+\-'])no-?reply@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    r"git@github\.com",
    r"@(example|github)\.(com|org|net|io|ai)",
    r"@(?:[a-zA-Z0-9\-]+\.)*(?:test|example|invalid|localhost)$",
    r"@example\.edu$",
    r"@(?:[a-zA-Z0-9\-]+\.)*internal$",
)]

_EDGE = " \t\r\n\"'`<>()[]{},;:"


def skip_file(path, kanbus_data):
    return bool(kanbus_data.search(path)) or any(p.search(path) for p in SKIP_PATHS)


def secret_shaped(value):
    """True when a `secret` span is really an id, digest, colour or date."""
    value = value.strip(_EDGE)
    return any(p.fullmatch(value) for p in SECRET_SHAPES)


def email_allowed(value):
    value = value.strip(_EDGE)
    return any(p.search(value) for p in EMAIL_ALLOW)


# --- Options --------------------------------------------------------------------

def parse_labels(text):
    """Default labels plus any extra comma-separated ones; unknown names raise ValueError."""
    labels = list(DEFAULT_LABELS)
    for name in (text or "").split(","):
        name = name.strip()
        if not name:
            continue
        if name not in ALL_LABELS:
            raise ValueError("Unknown label %r; choose from: %s." % (name, ", ".join(ALL_LABELS)))
        if name not in labels:
            labels.append(name)
    return tuple(labels)


def parse_threshold(text):
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise ValueError("--threshold must be a number between 0 and 1.")
    if not 0 <= value <= 1:
        raise ValueError("--threshold must be a number between 0 and 1.")
    return value


# --- Detector -------------------------------------------------------------------

def _normalise(label):
    return re.sub(r"^[BIESL]-", "", str(label)).lower()


class PrivacyFilter:
    """The real model, through the transformers token-classification pipeline (CPU)."""

    def __init__(self, notify=None, revision=None):
        self.notify = notify or (lambda message: None)
        # A Hugging Face commit hash pins the weights (the evaluation harness
        # does); None follows the model's default branch, as before.
        self.revision = revision
        self._pipeline = None

    def _load(self):
        try:
            from huggingface_hub import try_to_load_from_cache
            cached = isinstance(try_to_load_from_cache(MODEL, "config.json", revision=self.revision), str)
        except Exception:
            cached = False
        if not cached:
            self.notify(
                "Downloading the %s model (about 2.8 GB) to the Hugging Face cache; "
                "this happens once." % MODEL
            )
        try:
            from transformers import pipeline
            options = {"revision": self.revision} if self.revision else {}
            self._pipeline = pipeline(
                "token-classification", model=MODEL, aggregation_strategy="simple", device=-1, **options,
            )
        except ImportError:
            raise ExtraMissing()
        except Exception as exc:
            raise DeepScanError("Could not load the %s model (%s)." % (MODEL, type(exc).__name__))

    def __call__(self, text):
        if self._pipeline is None:
            self._load()
        spans = []
        for item in self._pipeline(text):
            spans.append((
                int(item["start"]), int(item["end"]),
                _normalise(item.get("entity_group") or item.get("entity")), float(item["score"]),
            ))
        return spans


def load_detector(notify=None, revision=None):
    """The detector to use: the test stub if DETECTOR_ENV names one, else the real model.

    ``revision`` pins the model to one Hugging Face commit (the stub ignores it).
    """
    spec = os.environ.get(DETECTOR_ENV)
    if spec:
        module, _, name = spec.partition(":")
        try:
            return getattr(importlib.import_module(module), name)()
        except ImportError:
            raise ExtraMissing()
        except Exception as exc:
            raise DeepScanError("Cannot load the detector named by %s (%s)." % (DETECTOR_ENV, type(exc).__name__))
    for package in ("transformers", "torch"):
        if importlib.util.find_spec(package) is None:
            raise ExtraMissing()
    return PrivacyFilter(notify, revision)


# --- Reading the diff -------------------------------------------------------------

def _git(repo_root, *args):
    proc = subprocess.run(
        ["git", "-c", "core.quotePath=false", *args], cwd=repo_root,
        capture_output=True, check=False, stdin=subprocess.DEVNULL,
    )
    if proc.returncode:
        raise DeepScanError("git %s failed." % args[0])
    return proc.stdout


_DIFF_FLAGS = ["-U0", "--no-color", "--no-ext-diff", "--no-renames"]


def staged_additions(repo_root):
    """[(path, line, text_bytes)] for every added line of the staged diff."""
    diff = _git(repo_root, "diff", "--cached", *_DIFF_FLAGS)
    return list(bypass._added_lines(diff))


def range_additions(repo_root, revisions):
    """The same for each non-merge commit in `revisions` (A..B), oldest first."""
    if ".." not in revisions:
        raise DeepScanError("--range must look like A..B.")
    diff = _git(repo_root, "log", "-p", "--reverse", "--no-merges", "--format=", *_DIFF_FLAGS,
                revisions, "--")
    return list(bypass._added_lines(diff))


# --- Scanning ---------------------------------------------------------------------

def _pieces(lines):
    """(line number, text sent to the model, whole line) with long lines windowed."""
    for number, text in lines:
        for i in range(0, max(len(text), 1), CHUNK_CHARS):
            yield number, text[i:i + CHUNK_CHARS], text


def _chunks(lines):
    chunk, size = [], 0
    for piece in _pieces(lines):
        if chunk and size + len(piece[1]) + 1 > CHUNK_CHARS:
            yield chunk
            chunk, size = [], 0
        chunk.append(piece)
        size += len(piece[1]) + 1
    if chunk:
        yield chunk


def scan(additions, detector, labels, threshold, kanbus_data):
    """Findings for the added lines.

    Each is a dict with File, RuleID, line, id, description, score. The id is
    the same hash `leftblock allow` records. The matched value is never kept.
    """
    by_file = {}
    for path, number, raw in additions:
        by_file.setdefault(path, []).append((number, raw.decode("utf-8", "replace")))
    found = {}
    for path, lines in by_file.items():
        if skip_file(path, kanbus_data):
            continue
        lines = [(n, t) for n, t in lines if t.strip() and not SKIP_LINE.search(t)]
        for chunk in _chunks(lines):
            text = "\n".join(piece[1] for piece in chunk)
            starts, at = [], 0
            for piece in chunk:
                starts.append(at)
                at += len(piece[1]) + 1
            for start, end, label, score in detector(text):
                if label not in labels or score < threshold or not 0 <= start < end <= len(text):
                    continue
                value = text[start:end]
                if label == "secret" and secret_shaped(value):
                    continue
                if label == "private_email" and email_allowed(value):
                    continue
                number, _, whole = chunk[bisect.bisect_right(starts, start) - 1]
                rule = RULE_PREFIX + label
                ident = allowlist.content_id(rule, path, whole)
                if ident in found and found[ident]["score"] >= score:
                    continue
                found[ident] = {
                    "File": path, "RuleID": rule, "line": number, "id": ident,
                    "description": "Privacy Filter: " + label, "score": score,
                }
    return sorted(found.values(), key=lambda f: (f["File"], f["line"], f["RuleID"]))
