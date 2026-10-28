"""Every external input the evaluation depends on, pinned in one place.

Change a value here on purpose, re-run ``python -m eval reproduce`` and commit
the new results; ``python -m eval compare`` then shows what moved. The pinned
Python packages live in ``eval/requirements.txt`` (parsed by ``requirements()``).
"""

import os
import re

# gitleaks: the same version CI installs (.github/workflows/ci.yml and eval.yml);
# a unit test keeps the three in step.
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_RELEASES = "https://github.com/gitleaks/gitleaks/releases/download"

# Samsung CredData, by commit. download_data.py's own snapshot.json pins the
# upstream repositories it clones, so the commit pins the data too.
CREDDATA_REPOSITORY = "https://github.com/Samsung/CredData.git"
CREDDATA_COMMIT = "fc9b64bed812fe2a10b83eaa4498a4ba8f3de5e4"

# The Privacy Filter weights, by Hugging Face commit (passed as ``revision=``).
MODEL_ID = "openai/privacy-filter"
MODEL_REVISION = "7ffa9a043d54d1be65afb281eddf0ffbe629385b"

# Defaults. The seed drives the generated corpus and the deep-scan sample.
DEFAULT_SEED = 20261028
DEFAULT_DEEP_SAMPLE = 1000

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(EVAL_DIR)
REQUIREMENTS = os.path.join(EVAL_DIR, "requirements.txt")
COMMITTED_RESULTS = os.path.join(EVAL_DIR, "results")

_PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)==([^\s;#]+)")


def requirements(path=REQUIREMENTS):
    """``{normalised package name: pinned version}`` from the requirements file."""
    pins = {}
    if not os.path.exists(path):
        return pins
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = _PIN.match(line)
            if match:
                pins[normalise(match.group(1))] = match.group(2)
    return pins


def normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()
