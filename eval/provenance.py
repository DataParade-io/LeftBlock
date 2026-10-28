"""Provenance: what exactly produced a results file.

Everything here is a version, a seed or a digest. Digests are SHA-256 over
file contents in a fixed order (paths sorted as POSIX strings), so they are
the same on every machine and operating system. No path, value or file
content is returned.
"""

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys

from eval import pins, tiers

SCHEMA = 1
# Packages whose versions are recorded when installed (the deep scan's stack).
PACKAGES = ("transformers", "torch", "tokenizers", "huggingface-hub", "safetensors", "numpy", "PyYAML", "pybase62")
IGNORED_NAMES = {".DS_Store"}


def sha256_of(*chunks):
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_sha256(root):
    """Digest of every file under ``root``: sorted POSIX relative paths and contents.

    Independent of directory listing order, file system and path separator.
    """
    entries = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_NAMES)
        for name in names:
            if name in IGNORED_NAMES:
                continue
            full = os.path.join(base, name)
            entries.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    digest = hashlib.sha256()
    for relative, full in sorted(entries):
        digest.update(relative.encode("utf-8") + b"\0" + file_sha256(full).encode() + b"\n")
    return digest.hexdigest(), len(entries)


def labels_sha256(clone):
    """Digest of CredData's ``meta/*.csv`` label files."""
    return tree_sha256(os.path.join(clone, "meta"))[0]


def tiers_sha256():
    """Digest of the tier definition (group -> category names, and the generic list)."""
    canonical = json.dumps({"groups": tiers.CRITICAL_GROUPS, "generic": tiers.GENERIC}, sort_keys=True, separators=(",", ":"))
    return sha256_of(canonical.encode("utf-8"))


def ruleset_sha256():
    from eval import detectors
    return file_sha256(detectors.SHIPPED_CONFIG)


def sample_sha256(sample):
    """Digest of a deep-scan sample: each unit's key, truth and weight, sorted."""
    rows = sorted("%s\t%d\t%d\t%s\t%.9f" % (u.file, u.start, u.end, u.truth, u.weight) for u in sample)
    return sha256_of("\n".join(rows).encode("utf-8"))


def package_versions():
    found = {}
    for name in PACKAGES:
        try:
            found[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return found


def git_state():
    """``{"sha", "dirty"}`` of the LeftBlock checkout, or ``{"sha": None}`` outside one."""
    def git(*args):
        proc = subprocess.run(["git", "-C", pins.REPO_ROOT, *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        return proc.stdout.strip() if proc.returncode == 0 else None
    sha = git("rev-parse", "HEAD")
    if not sha:
        return {"sha": None, "dirty": None}
    return {"sha": sha, "dirty": bool(git("status", "--porcelain", "--untracked-files=no"))}


def environment():
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "packages": package_versions(),
    }


def deep_scan_settings(detector_names_used, torch_threads=None):
    """The model settings, or None when no deep scan was part of the run."""
    from leftblock import deep
    if not detector_names_used:
        return None
    return {
        "model": pins.MODEL_ID,
        "revision": pins.MODEL_REVISION,
        "labels": list(deep.DEFAULT_LABELS),
        "threshold": deep.DEFAULT_THRESHOLD,
        "device": "cpu",
        "torch_threads": torch_threads,
        "stub": bool(os.environ.get(deep.DETECTOR_ENV)),
    }


def torch_threads():
    if "torch" not in sys.modules:
        return None
    try:
        return sys.modules["torch"].get_num_threads()
    except Exception:
        return None


def collect(leftblock_version, gitleaks, arguments, deep_used):
    """The top-level ``provenance`` block of a results file.

    ``gitleaks`` is ``{"version", "pinned", "matches_pin"}``; ``arguments`` the
    run settings that change the numbers (never a path).
    """
    state = git_state()
    return {
        "schema": SCHEMA,
        "leftblock": {"version": leftblock_version, "git_sha": state["sha"], "git_dirty": state["dirty"]},
        "gitleaks": gitleaks,
        "eval": {"tiers_sha256": tiers_sha256(), "ruleset_sha256": ruleset_sha256()},
        "deep_scan": deep_scan_settings(deep_used, torch_threads()),
        "arguments": arguments,
        "environment": environment(),
    }
