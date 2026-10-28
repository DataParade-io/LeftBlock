"""CredData: loading labels, drawing the deep-scan sample, and the pinned download.

Layout under the data directory ``ROOT``::

    ROOT/CredData/meta/*.csv         labels (from the pinned clone of github.com/Samsung/CredData)
    ROOT/CredData/data/<repo>/...    the obfuscated files that ``download_data.py`` writes

A label's ``FilePath`` starts with ``data/``, so it is a path relative to the
clone (``ROOT/CredData``) and doubles as the file id. Nothing here ever
returns or prints a value.
"""

import csv
import glob
import os
import random
import re
import shutil
import subprocess
import sys

from eval import datadir, scoring, tiers

REPOSITORY = "https://github.com/Samsung/CredData.git"
PINNED_COMMIT = "fc9b64bed812fe2a10b83eaa4498a4ba8f3de5e4"

# The download needs about 10 GB of scratch space (shallow clones of 297
# repositories, then the 11k selected files); refuse to start with less than
# this much free so the disk is never filled.
MIN_FREE_GB_TO_FETCH = 30

CONTEXT_LINES = 5   # deep-scan window radius
MIN_PER_STRATUM = 3  # every stratum keeps at least this many sampled units (or all of it)


def paths(root):
    """(clone directory, dataset directory); file ids are relative to the clone."""
    clone = os.path.join(root, "CredData")
    return clone, os.path.join(clone, "data")


def load(root):
    """Read the labels and return ``{"units", "excluded", "rows", "missing_files"}``.

    ``units`` hold T and F line ranges only; ``excluded`` counts the X-only
    ranges that were left out; ``rows`` counts the raw labelled rows by truth;
    ``labelled`` is every (file, line) any row labels, X included.
    """
    clone, _ = paths(root)
    rows, row_counts, missing, seen_files = [], {"T": 0, "F": 0, "X": 0}, 0, {}
    labelled = set()
    for meta in sorted(glob.glob(os.path.join(clone, "meta", "*.csv"))):
        with open(meta, newline="", encoding="utf-8") as handle:
            for record in csv.DictReader(handle):
                truth = record["GroundTruth"]
                if truth not in row_counts:
                    continue
                path = record["FilePath"]
                if path not in seen_files:
                    seen_files[path] = os.path.isfile(os.path.join(clone, path))
                if not seen_files[path]:
                    missing += 1
                    continue
                row_counts[truth] += 1
                categories = [c for c in record["Category"].split(":") if c] or ["(none)"]
                start, end = int(record["LineStart"]), int(record["LineEnd"])
                labelled.update((path, line) for line in range(start, end + 1))
                rows.append((path, start, end, truth, categories))
    units, excluded = scoring.merge_rows(rows)
    return {"units": units, "excluded": excluded, "rows": row_counts, "missing_rows": missing, "labelled": labelled,
            "files": sum(1 for ok in seen_files.values() if ok)}


def primary_stratum(unit):
    """Stratum key: truth, whether the unit is in the critical tier, first category."""
    return (unit.truth, tiers.in_tier(unit.categories, tiers.CRITICAL), unit.categories[0])


def select_sample(units, rest_size, seed):
    """Choose the units the deep scan will see, with population weights.

    Every critical-tier true unit is taken (weight 1). The rest (all other
    true units and every false unit) is sampled per stratum
    (truth, critical?, primary category), proportionally to ``rest_size`` with
    at least MIN_PER_STRATUM per stratum. Each sampled unit carries the weight
    N_stratum / n_stratum so population rates can be estimated from the sample.
    Deterministic for a given ``seed``.
    """
    census = [u for u in units if u.truth == "T" and tiers.in_tier(u.categories, tiers.CRITICAL)]
    rest = [u for u in units if not (u.truth == "T" and tiers.in_tier(u.categories, tiers.CRITICAL))]
    strata = {}
    for unit in rest:
        strata.setdefault(primary_stratum(unit), []).append(unit)
    rng = random.Random(seed)
    chosen = [u._replace(weight=1.0) for u in census]
    for key in sorted(strata, key=repr):
        members = strata[key]
        take = min(len(members), max(MIN_PER_STRATUM, int(round(rest_size * len(members) / max(1, len(rest))))))
        weight = len(members) / take
        for unit in rng.sample(members, take):
            chosen.append(unit._replace(weight=weight))
    return chosen


def line_counts(root, files):
    """Number of lines per file; ``root`` is the directory the file ids are relative to."""
    counts = {}
    for path in files:
        with open(os.path.join(root, path), "rb") as handle:
            counts[path] = handle.read().count(b"\n") + 1
    return counts


def fetch(root, log=print):
    """Clone CredData at the pinned commit and run its ``download_data.py`` into ROOT/data."""
    root = datadir.require_outside_git(root)
    clone, data = paths(root)
    os.makedirs(root, exist_ok=True)
    if os.path.isdir(data):
        log("Dataset already present at the data directory; nothing to fetch.")
        return 0
    free_gb = shutil.disk_usage(root).free / 2 ** 30
    if free_gb < MIN_FREE_GB_TO_FETCH:
        log("Only %.0f GB free; the download needs about %d GB of headroom. Stopping." % (free_gb, MIN_FREE_GB_TO_FETCH))
        return 2
    if not os.path.isdir(clone):
        subprocess.run(["git", "clone", "-q", REPOSITORY, clone], check=True)
    subprocess.run(["git", "-C", clone, "checkout", "-q", PINNED_COMMIT], check=True)
    log("Running download_data.py (shallow clones of 297 repositories; tens of minutes).")
    # download_data.py reads snapshot.json from its working directory, and its
    # labels name files as "data/...", so --data_dir must be the relative "data".
    code = subprocess.run(
        [sys.executable, "download_data.py", "--data_dir", "data", "--jobs", "6"], cwd=clone,
    ).returncode
    if code == 0:
        shutil.rmtree(os.path.join(clone, "tmp"), ignore_errors=True)
    return code


# --- How CredData rewrote AWS access key ids -------------------------------------

# The shape gitleaks' aws-access-token rule can match (base32 tail, 4 known prefixes).
GITLEAKS_AWS_SHAPE = re.compile(r"(?<![A-Za-z0-9])(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Za-z0-9])")


def aws_probe(root):
    """Counts (never values) describing the obfuscated "AWS Client ID" labels, and the shape-valid subset.

    Returns ``(counts, shape_valid)``: ``counts`` is a dict of integers;
    ``shape_valid`` the set of ``(file, start, end)`` unit keys whose value is
    still shaped like an access key id gitleaks can match. CredData keeps the
    key's prefix (AKIA, ASIA, AIDA, ...) and replaces the rest with random
    same-length text, so we check how many are still matchable and whether the
    documented ``...EXAMPLE`` values (which gitleaks allowlists) appear.
    """
    clone, _ = paths(root)
    counts = {"labelled_t_rows": 0, "value_position_missing": 0, "ends_with_EXAMPLE": 0,
              "contains_example_any_case": 0, "gitleaks_prefix_and_shape": 0,
              "gitleaks_prefix_but_tail_outside_base32": 0, "iam_id_prefix_not_covered_by_gitleaks": 0}
    shape_valid, cache = set(), {}
    for meta in sorted(glob.glob(os.path.join(clone, "meta", "*.csv"))):
        with open(meta, newline="", encoding="utf-8") as handle:
            for record in csv.DictReader(handle):
                if record["GroundTruth"] != "T" or "AWS Client ID" not in record["Category"].split(":"):
                    continue
                counts["labelled_t_rows"] += 1
                if not record["ValueStart"]:
                    counts["value_position_missing"] += 1
                    continue
                path = record["FilePath"]
                if path not in cache:
                    with open(os.path.join(clone, path), "rb") as source:
                        cache[path] = source.read().split(b"\n")
                line = cache[path][int(record["LineStart"]) - 1].decode("utf-8", "replace")
                value = line[int(record["ValueStart"]):int(record["ValueEnd"])]
                if value.endswith("EXAMPLE"):
                    counts["ends_with_EXAMPLE"] += 1
                if "example" in value.lower():
                    counts["contains_example_any_case"] += 1
                if GITLEAKS_AWS_SHAPE.search(value):
                    counts["gitleaks_prefix_and_shape"] += 1
                    shape_valid.add((path, int(record["LineStart"]), int(record["LineEnd"])))
                elif re.match(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)", value):
                    counts["gitleaks_prefix_but_tail_outside_base32"] += 1
                else:
                    counts["iam_id_prefix_not_covered_by_gitleaks"] += 1
    return counts, shape_valid
