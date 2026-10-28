"""Where evaluation data may live: never inside a Git repository.

CredData holds obfuscated but credential-shaped text for ~11k files. If it sat
inside a working tree, a pre-commit gate (this one!) or a push scan would see
it and a careless ``git add .`` could commit it. The harness therefore
refuses a data directory that is inside any Git repository, and the
repository's .gitignore also lists the usual download names as a second guard.
"""

import os
import subprocess


class DataDirError(Exception):
    pass


def containing_repository(path):
    """The top-level directory of the Git repository holding ``path``, or None."""
    path = os.path.realpath(path)
    probe = path
    while not os.path.isdir(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            return None
        probe = parent
    proc = subprocess.run(
        ["git", "-C", probe, "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    if proc.returncode:
        return None
    return proc.stdout.strip() or None


def require_outside_git(path):
    """Return the resolved ``path``; raise DataDirError when it is inside a repository."""
    resolved = os.path.realpath(path)
    top = containing_repository(resolved)
    if top:
        raise DataDirError(
            "Refusing the data directory %s: it is inside a Git repository. "
            "Choose a directory outside any repository (for example under /tmp)." % path
        )
    return resolved
