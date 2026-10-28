"""Labelled units and how detectors are scored against them.

A unit is one labelled line range of one file: ``file`` (an id relative to the
corpus root), ``start``..``end`` (1-based, inclusive; one line except for
multi-line labels such as PEM keys), ``truth`` ("T" or "F"), the categories it
carries and a sampling ``weight`` (1.0 unless the unit was drawn from a
stratified sample). A detector's output is its set of flagged ``(file, line)``
pairs; a unit is hit when any of its lines is flagged.
"""

from collections import namedtuple

from eval import stats, tiers

Unit = namedtuple("Unit", "file start end truth categories tags weight")


def make_unit(file, start, end, truth, categories, tags=None, weight=1.0):
    return Unit(file, start, end, truth, tuple(categories), dict(tags or {}), weight)


def merge_rows(rows):
    """Collapse raw labelled rows into units.

    ``rows`` are ``(file, start, end, truth, categories)`` with truth in T/F/X.
    Rows covering the same range are merged: T beats F beats X, and the
    categories of every row with the winning truth are kept (so a line that is
    both a password and a username label counts under both). Returns
    ``(units, excluded)`` where units hold only T and F ranges and
    ``excluded`` counts the ranges whose every row was X.
    """
    ranges = {}
    for file, start, end, truth, categories in rows:
        ranges.setdefault((file, start, end), []).append((truth, categories))
    units, excluded = [], 0
    for (file, start, end), entries in sorted(ranges.items()):
        truths = {truth for truth, _ in entries}
        winner = "T" if "T" in truths else "F" if "F" in truths else None
        if winner is None:
            excluded += 1
            continue
        cats = []
        for truth, categories in entries:
            if truth == winner:
                cats.extend(c for c in categories if c not in cats)
        units.append(make_unit(file, start, end, winner, cats))
    return units, excluded


def hit_units(units, flagged):
    """The units any of whose lines is in ``flagged`` (a set of (file, line))."""
    hits = set()
    for index, unit in enumerate(units):
        for line in range(unit.start, unit.end + 1):
            if (unit.file, line) in flagged:
                hits.add(index)
                break
    return hits


def metrics(units, hits):
    """Recall and precision of one detector over ``units``.

    ``hits`` is the set of unit indexes the detector hit. Returns raw counts,
    weighted (population-estimated) counts and rates with Wilson intervals.
    """
    raw = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    weighted = {"tp": 0.0, "fp": 0.0, "fn": 0.0, "tn": 0.0}
    at_risk_t, at_risk_hit, tp_w, hit_w = [], [], [], []
    for index, unit in enumerate(units):
        hit = index in hits
        key = ("tp" if hit else "fn") if unit.truth == "T" else ("fp" if hit else "tn")
        raw[key] += 1
        weighted[key] += unit.weight
        if unit.truth == "T":
            at_risk_t.append(unit.weight)
            if hit:
                tp_w.append(unit.weight)
        if hit:
            at_risk_hit.append(unit.weight)
    return {
        "counts": raw,
        "estimated": {k: round(v, 2) for k, v in weighted.items()},
        "recall": stats.rate(tp_w, at_risk_t),
        "precision": stats.rate(tp_w, at_risk_hit),
    }


def breakdown(units, hits):
    """Metrics overall, per tier and per category (a unit counts under each of its categories)."""
    result = {
        "overall": metrics(units, hits),
        "critical": subset_metrics(units, hits, lambda u: tiers.in_tier(u.categories, tiers.CRITICAL)),
        "broad": subset_metrics(units, hits, lambda u: tiers.in_tier(u.categories, tiers.BROAD)),
        "groups": {},
        "categories": {},
    }
    for group in tiers.CRITICAL_GROUPS:
        result["groups"][group] = subset_metrics(
            units, hits, lambda u, g=group: any(tiers.group_of(c) == g for c in u.categories))
    for category in sorted({c for u in units for c in u.categories}):
        result["categories"][category] = subset_metrics(units, hits, lambda u, c=category: c in u.categories)
    return result


def subset_metrics(units, hits, predicate):
    chosen = [i for i, u in enumerate(units) if predicate(u)]
    return metrics([units[i] for i in chosen], {n for n, i in enumerate(chosen) if i in hits})
