"""Side-by-side view of two results files. Informational: it never judges."""

import json

from eval import tiers

SKIP = {"seconds", "seconds_total"}


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def flatten(node, prefix=()):
    if isinstance(node, dict):
        for key in sorted(node):
            if key in SKIP:
                continue
            yield from flatten(node[key], prefix + (key,))
    else:
        yield prefix, node


def windows_comparable(a, b, dataset):
    """False when the two deep-scan samples differ (a smoke run, another size or seed): those numbers are not comparable."""
    def sample(results):
        return (results.get("datasets", {}).get(dataset, {}).get("windows") or {}).get("sample")
    sa, sb = sample(a), sample(b)
    if not sa or not sb:
        return True
    return sa.get("sha256") == sb.get("sha256") and not sa.get("smoke_files") and not sb.get("smoke_files")


def without_windows(results, dataset):
    clone = json.loads(json.dumps(results))
    clone.get("datasets", {}).get(dataset, {}).pop("windows", None)
    return clone


def headline(results):
    """``{(dataset, scope, detector, tier): (recall, precision)}`` for the headline numbers."""
    rows = {}
    for dataset, record in sorted(results.get("datasets", {}).items()):
        for scope in ("full_files", "windows"):
            section = record.get(scope)
            if not section:
                continue
            for detector, entry in sorted(section["detectors"].items()):
                for tier in ("overall", tiers.CRITICAL):
                    m = entry[tier]
                    rows[(dataset, scope, detector, tier)] = (m["recall"]["value"], m["precision"]["value"])
    return rows


def fmt(value):
    return "n/a" if value is None else "%.1f%%" % (100 * value)


def provenance_diff(a, b):
    pa = dict(flatten(a.get("provenance", {})))
    pb = dict(flatten(b.get("provenance", {})))
    for dataset in sorted(set(a.get("datasets", {})) | set(b.get("datasets", {}))):
        for side, target in ((a, pa), (b, pb)):
            record = side.get("datasets", {}).get(dataset, {})
            for path, value in flatten(record.get("inputs", {})):
                target[(dataset,) + path] = value
    return [(".".join(k), pa.get(k, "(absent)"), pb.get(k, "(absent)"))
            for k in sorted(set(pa) | set(pb)) if pa.get(k, "(absent)") != pb.get(k, "(absent)")]


def render(a, b, name_a="A", name_b="B"):
    notes = []
    for dataset in sorted(set(a.get("datasets", {})) & set(b.get("datasets", {}))):
        if not windows_comparable(a, b, dataset):
            a, b = without_windows(a, dataset), without_windows(b, dataset)
            notes.append("%s: the deep-scan samples differ (a smoke run, or another size or seed), so the sample (`windows`) numbers are not compared." % dataset)
    out = ["# Results comparison", "", "A = %s, B = %s. Differences only; nothing here is a pass or fail." % (name_a, name_b), ""]
    out += [n + "\n" for n in notes]
    ha, hb = headline(a), headline(b)
    out += ["## Headline recall / precision", "", "| dataset | scope | detector | tier | A recall | B recall | A precision | B precision |", "|---|---|---|---|---|---|---|---|"]
    shown = 0
    for key in sorted(set(ha) | set(hb)):
        ra, rb = ha.get(key), hb.get(key)
        if ra is None or rb is None:
            continue
        out.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (*key, fmt(ra[0]), fmt(rb[0]), fmt(ra[1]), fmt(rb[1])))
        shown += 1
    if not shown:
        out.append("| (no scope present in both files) | | | | | | | |")
    only = sorted({k[:3] for k in set(ha) ^ set(hb)})
    if only:
        out += ["", "Present in only one file (not compared): " + ", ".join("/".join(k) for k in only) + "."]
    fa, fb = dict(flatten(a.get("datasets", {}))), dict(flatten(b.get("datasets", {})))
    changed = [k for k in sorted(set(fa) & set(fb)) if fa[k] != fb[k]]
    out += ["", "## Values that differ", "",
            "%d of %d shared values differ (counts, rates and estimates; timings excluded)." % (len(changed), len(set(fa) & set(fb)))]
    for k in changed[:40]:
        out.append("- `%s`: %s -> %s" % (".".join(k), fa[k], fb[k]))
    if len(changed) > 40:
        out.append("- ... and %d more." % (len(changed) - 40))
    out += ["", "## Inputs and environment that differ", ""]
    diffs = provenance_diff(a, b)
    if not diffs:
        out.append("None: same pins, versions and environment.")
    for path, va, vb in diffs:
        out.append("- `%s`: %s -> %s" % (path, va, vb))
    return "\n".join(out) + "\n"
