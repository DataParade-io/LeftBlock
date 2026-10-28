"""Running a dataset through the detectors and assembling the result record.

The record holds counts, rates and category names only: no values, no file
contents and no file paths (CredData files are identified only by the
obfuscated ids already in its labels, and those never leave this module).
"""

import os
import shutil
import time

from eval import creddata, detectors, generated, pins, provenance, scoring, tiers, windows

DEFAULT_SEED = pins.DEFAULT_SEED
DEFAULT_DEEP_SAMPLE = pins.DEFAULT_DEEP_SAMPLE  # chosen so the whole run takes roughly 1.5 h; see eval/README.md
MODEL_SECONDS_PER_KB = 2.0  # one process, Apple M1 Max, machine otherwise busy; 1.1 when idle


def unit_counts(units, excluded, rows=None, files=None):
    record = {
        "labelled_lines": len(units),
        "true": sum(1 for u in units if u.truth == "T"),
        "false": sum(1 for u in units if u.truth == "F"),
        "excluded_x_lines": excluded,
        "multi_line_units": sum(1 for u in units if u.end > u.start),
        "critical_true": sum(1 for u in units if u.truth == "T" and tiers.in_tier(u.categories, tiers.CRITICAL)),
        "critical_false": sum(1 for u in units if u.truth == "F" and tiers.in_tier(u.categories, tiers.CRITICAL)),
    }
    if rows is not None:
        record["label_rows"] = rows
    if files is not None:
        record["files"] = files
    return record


def compare(units, base, new):
    """What ``new`` adds over ``base``: true units only it hits, and false units only it hits."""
    def tally(wanted):
        chosen = [i for i in new - base if units[i].truth == wanted]
        by_category = {}
        for i in chosen:
            for category in units[i].categories:
                slot = by_category.setdefault(category, {"count": 0, "estimated": 0.0})
                slot["count"] += 1
                slot["estimated"] += units[i].weight
        critical = [i for i in chosen if tiers.in_tier(units[i].categories, tiers.CRITICAL)]
        return {
            "count": len(chosen), "estimated": round(sum(units[i].weight for i in chosen), 2),
            "critical_count": len(critical), "critical_estimated": round(sum(units[i].weight for i in critical), 2),
            "by_category": {k: {"count": v["count"], "estimated": round(v["estimated"], 2)} for k, v in sorted(by_category.items())},
        }
    return {"new_true_positives": tally("T"), "new_false_positives": tally("F")}


def tag_breakdown(units, hits, tag):
    values = sorted({u.tags[tag] for u in units if tag in u.tags})
    return {value: scoring.subset_metrics(units, hits, lambda u, v=value: u.tags.get(tag) == v) for value in values}


def rule_tally(units, hits, flags, truth, critical_only=False, limit=12):
    """``[[rule, units]]``: which rules flagged the hit units of one truth value (most frequent first)."""
    tally = {}
    for index in hits:
        unit = units[index]
        if unit.truth != truth or (critical_only and not tiers.in_tier(unit.categories, tiers.CRITICAL)):
            continue
        rules = set()
        for line in range(unit.start, unit.end + 1):
            rules.update(flags.line_rules.get((unit.file, line), ()))
        for rule in rules:
            tally[rule] = tally.get(rule, 0) + 1
    return [[rule, n] for rule, n in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def evaluate(units, flags, extra_subsets=None):
    """Breakdowns per detector, and what each layer adds over the one before."""
    hits = {name: scoring.hit_units(units, f.lines) for name, f in flags.items()}
    result = {"detectors": {}, "adds": {}}
    for name, h in hits.items():
        entry = scoring.breakdown(units, h)
        entry["rules"] = {
            "false_positive_units": rule_tally(units, h, flags[name], "F"),
            "false_positive_units_critical": rule_tally(units, h, flags[name], "F", critical_only=True),
            "true_positive_units": rule_tally(units, h, flags[name], "T"),
        }
        for label, predicate in (extra_subsets or {}).items():
            entry.setdefault("subsets", {})[label] = scoring.subset_metrics(units, h, predicate)
        result["detectors"][name] = entry
    pairs = ((detectors.LEFTBLOCK, detectors.STOCK), (detectors.DEEP, detectors.LEFTBLOCK), (detectors.COMBINED, detectors.LEFTBLOCK))
    for new, base in pairs:
        if new in hits and base in hits:
            result["adds"]["%s_over_%s" % (new, base)] = compare(units, hits[base], hits[new])
    return result, hits


def unlabelled(flags, labelled):
    """Findings (and distinct lines) that touch no labelled line at all."""
    count, lines = 0, set()
    for file, start, end in flags.items:
        span = range(start, end + 1)
        if any((file, line) in labelled for line in span):
            continue
        count += 1
        lines.update((file, line) for line in span)
    return {"findings": count, "distinct_lines": len(lines), "all_findings": flags.findings,
            "findings_by_rule_all": [[r, n] for r, n in sorted(flags.by_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:15]]}


def combine(flags):
    out = dict(flags)
    if detectors.LEFTBLOCK in flags and detectors.DEEP in flags:
        out[detectors.COMBINED] = flags[detectors.LEFTBLOCK].union(flags[detectors.DEEP])
    return out


def expand_selection(selected):
    selected = set(selected)
    if detectors.COMBINED in selected:
        selected |= {detectors.LEFTBLOCK, detectors.DEEP}
    return selected


def timing_of(flags):
    return {name: round(f.seconds, 1) for name, f in flags.items()}


def run_creddata(root, selected, seed, deep_sample, work, log=print, shard=None, smoke_files=None):
    started = time.time()
    selected = expand_selection(selected)
    clone, _ = creddata.paths(root)
    loaded = creddata.load(root)
    units = loaded["units"]
    log("loaded %d labelled lines (%d true, %d false), %d excluded as X" % (
        len(units), sum(u.truth == "T" for u in units), sum(u.truth == "F" for u in units), loaded["excluded"]))
    if shard:
        return deep_shard(root, units, seed, deep_sample, work, log, shard, smoke_files)
    aws_counts, aws_valid = creddata.aws_probe(root)
    subsets = {"AWS Client ID, key still gitleaks-shaped": lambda u: (u.file, u.start, u.end) in aws_valid}

    record = {"pin": creddata.PINNED_COMMIT, "seed": seed, "deep_sample_requested": deep_sample,
              "inputs": creddata.inputs(root, loaded),
              "units": unit_counts(units, loaded["excluded"], loaded["rows"], loaded["files"]),
              "probes": {"aws_client_id": aws_counts}}

    # --- full files: gitleaks only (the model cannot read 19M lines) -----------------
    full = {}
    data_dir = creddata.paths(root)[1]
    if detectors.STOCK in selected:
        log("gitleaks (stock) on the full dataset")
        full[detectors.STOCK] = detectors.run_gitleaks(data_dir, None, prefix="data/")
    if detectors.LEFTBLOCK in selected:
        log("gitleaks (LeftBlock ruleset) on the full dataset")
        full[detectors.LEFTBLOCK] = detectors.run_gitleaks(data_dir, detectors.SHIPPED_CONFIG, prefix="data/")
    result, _ = evaluate(units, full, subsets)
    record["full_files"] = result
    record["unlabelled_flags"] = {name: unlabelled(f, loaded["labelled"]) for name, f in full.items()}

    # --- windows: every detector on the same sample ---------------------------------
    if detectors.DEEP in selected or detectors.COMBINED in selected:
        sample, wins, extra = deep_window_input(root, units, seed, deep_sample, smoke_files)
        kb = sum(len(t) + 1 for _, _, t in extra) / 1024
        log("deep sample: %d lines in %d files, %d context lines, %.0f KB for the model (about %.0f min)" % (
            len(sample), len(wins), len(extra), kb, kb * MODEL_SECONDS_PER_KB / 60))
        blank_root = os.path.join(work, "windows")
        shutil.rmtree(blank_root, ignore_errors=True)
        windows.write_blanked(clone, blank_root, wins)
        flags = {}
        if detectors.STOCK in selected:
            flags[detectors.STOCK] = detectors.run_gitleaks(blank_root, None)
        flags[detectors.LEFTBLOCK] = detectors.run_gitleaks(blank_root, detectors.SHIPPED_CONFIG)
        cache = os.path.join(work, "deep-cache-%d-%d.jsonl" % (seed, deep_sample))
        flags[detectors.DEEP], deep_bytes = detectors.run_deep(extra, cache, log, revision=pins.MODEL_REVISION)
        flags = combine(flags)
        subsets_w = {"AWS Client ID, key still gitleaks-shaped": lambda u: (u.file, u.start, u.end) in aws_valid}
        result, _ = evaluate(sample, flags, subsets_w)
        result["sample"] = {
            "units": len(sample),
            "critical_true_census": sum(1 for u in sample if u.truth == "T" and tiers.in_tier(u.categories, tiers.CRITICAL)),
            "other_sampled": sum(1 for u in sample if not (u.truth == "T" and tiers.in_tier(u.categories, tiers.CRITICAL))),
            "files": len(wins), "context_lines_radius": creddata.CONTEXT_LINES,
            "model_kb": round(deep_bytes / 1024, 1),
            "min_per_stratum": creddata.MIN_PER_STRATUM,
            "sha256": provenance.sample_sha256(sample),
            "smoke_files": smoke_files,  # set: a pipeline check on a few files, not a population estimate
        }
        result["seconds"] = timing_of(flags)
        record["windows"] = result
    record["seconds_total"] = round(time.time() - started, 1)
    return record


def deep_window_input(root, units, seed, deep_sample, smoke_files=None):
    """The sample, its context windows and the lines the model reads."""
    clone, _ = creddata.paths(root)
    sample = creddata.select_sample(units, deep_sample, seed)
    if smoke_files:
        sample = creddata.smoke_subset(sample, smoke_files, seed)
    counts = creddata.line_counts(clone, {u.file for u in sample})
    wins = windows.window_lines(sample, counts, creddata.CONTEXT_LINES)
    return sample, wins, windows.additions(clone, wins)


def deep_shard(root, units, seed, deep_sample, work, log, shard, smoke_files=None):
    """Scan one shard of the deep-scan input into the cache; no scoring."""
    _, _, extra = deep_window_input(root, units, seed, deep_sample, smoke_files)
    cache = os.path.join(work, "deep-cache-%d-%d.jsonl" % (seed, deep_sample))
    detectors.run_deep(extra, cache, log, shard, revision=pins.MODEL_REVISION)
    return None


def run_generated(root, selected, seed, work, log=print):
    started = time.time()
    selected = expand_selection(selected)
    corpus = os.path.join(work, "corpus")
    shutil.rmtree(corpus, ignore_errors=True)
    os.makedirs(corpus)
    units, info = generated.generate(corpus, seed)
    log("generated %d files, %d labelled lines" % (info["files"], len(units)))
    flags = {}
    if detectors.STOCK in selected:
        flags[detectors.STOCK] = detectors.run_gitleaks(corpus, None)
    if detectors.LEFTBLOCK in selected:
        flags[detectors.LEFTBLOCK] = detectors.run_gitleaks(corpus, detectors.SHIPPED_CONFIG)
    corpus_digest = provenance.tree_sha256(corpus)[0]
    if detectors.DEEP in selected:
        lines = []
        for file in sorted({u.file for u in units}):
            for number, text in enumerate(windows.read_lines(corpus, file), start=1):
                if text.strip():
                    lines.append((file, number, text.rstrip(b"\r")))
        flags[detectors.DEEP], deep_bytes = detectors.run_deep(lines, os.path.join(work, "deep-cache-generated-%d.jsonl" % seed), log, revision=pins.MODEL_REVISION)
    flags = combine(flags)
    result, hits = evaluate(units, flags)
    record = {"seed": seed, "inputs": {"seed": seed, "corpus_sha256": corpus_digest, "files": info["files"]},
              "units": unit_counts(units, 0, None, info["files"]), "full_files": result,
              "seconds": timing_of(flags), "seconds_total": round(time.time() - started, 1), "tags": {}}
    for name, h in hits.items():
        record["tags"][name] = {tag: tag_breakdown(units, h, tag) for tag in ("context", "flavour", "negkind")}
    shutil.rmtree(corpus, ignore_errors=True)
    return record
