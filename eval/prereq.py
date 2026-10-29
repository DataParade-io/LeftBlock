"""Prerequisite checks: what is missing, and the exact command that fixes it."""

import importlib.util
import os
import platform
import shutil
import sys
from collections import namedtuple

from eval import creddata, datadir, detectors, pins

Problem = namedtuple("Problem", "what fix")

MIN_FREE_GB_DEEP = 6  # model weights (2.8 GB) plus the Hugging Face download copy


def gitleaks_asset():
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}.get(platform.machine())
    if not (system and arch):
        return None
    return "gitleaks_%s_%s_%s.tar.gz" % (pins.GITLEAKS_VERSION, system, arch)


def gitleaks_install_hint():
    asset = gitleaks_asset()
    if not asset:
        return ("download gitleaks v%s for your platform from %s/v%s/ and put it on PATH"
                % (pins.GITLEAKS_VERSION, pins.GITLEAKS_RELEASES, pins.GITLEAKS_VERSION))
    return ('mkdir -p ~/.local/bin && curl -sSfL "%s/v%s/%s" | tar -xz -C ~/.local/bin gitleaks '
            '&& export PATH="$HOME/.local/bin:$PATH"' % (pins.GITLEAKS_RELEASES, pins.GITLEAKS_VERSION, asset))


def check(data_dir, skip_deep, allow_gitleaks_mismatch=False):
    """Return ``(problems, notes)``: blocking problems, and what was found."""
    problems, notes = [], []
    if shutil.which("git") is None:
        problems.append(Problem("git is not installed.", "install git (macOS: xcode-select --install; Debian/Ubuntu: sudo apt-get install git)."))
    if shutil.which("gitleaks") is None:
        problems.append(Problem("gitleaks is not installed.", gitleaks_install_hint()))
    else:
        try:
            state = detectors.gitleaks_state(allow_gitleaks_mismatch, warn=notes.append)
            notes.append("gitleaks %s%s" % (state["version"], "" if state["matches_pin"] else " (NOT the pinned %s)" % state["pinned"]))
        except detectors.GitleaksMismatch as exc:
            problems.append(Problem(str(exc).split(" Pass --allow")[0], gitleaks_install_hint()))
    try:
        datadir.require_outside_git(data_dir)
    except datadir.DataDirError:
        problems.append(Problem("The data directory %s is inside a Git repository." % data_dir,
                                "choose another with --data-dir (the default is ~/.cache/leftblock-eval)."))
    if not creddata.fetched(data_dir):
        if os.path.isdir(creddata.paths(data_dir)[1]):
            problems.append(Problem("The CredData download in %s did not finish." % data_dir,
                                    "delete %s and run again." % creddata.paths(data_dir)[0]))
        else:
            if importlib.util.find_spec("base62") is None:
                problems.append(Problem("CredData's download script needs the Python package pybase62.",
                                        "%s -m pip install -r eval/requirements.txt" % sys.executable))
            probe = data_dir
            while not os.path.isdir(probe) and os.path.dirname(probe) != probe:
                probe = os.path.dirname(probe)
            free = shutil.disk_usage(probe).free / 2 ** 30
            if free < creddata.MIN_FREE_GB_TO_FETCH:
                problems.append(Problem("%.0f GB free where the data goes; the download peaks at about %d GB (about 1 GB is kept)."
                                        % (free, creddata.MIN_FREE_GB_TO_FETCH), "free some space or pick another --data-dir."))
    if not skip_deep:
        from leftblock import deep
        try:
            deep.load_detector(None, pins.MODEL_REVISION)
        except deep.ExtraMissing:
            problems.append(Problem("The deep scan needs the model libraries (transformers and torch).",
                                    "%s -m pip install -r eval/requirements.txt   (or use --skip-deep)" % sys.executable))
        else:
            wrong = []
            from eval import provenance
            have = provenance.package_versions()
            for name, version in sorted(pins.requirements().items()):
                if name in have and have[name].split("+")[0] != version:
                    wrong.append("%s %s (pinned %s)" % (name, have[name], version))
            if wrong:
                notes.append("WARNING: package versions differ from eval/requirements.txt: " + ", ".join(wrong))
    return problems, notes
