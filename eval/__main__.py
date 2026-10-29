"""``python -m eval``: reproduce, fetch, run, report, compare and check.

Run it from the repository root (``eval/`` is not an installed package).
"""

import argparse
import json
import os
import subprocess
import sys
import time

from eval import compare, creddata, datadir, detectors, pins, prereq, provenance, report, runner

ALIASES = {"stock": detectors.STOCK, "leftblock": detectors.LEFTBLOCK, "deep": detectors.DEEP, "combined": detectors.COMBINED}
DATASETS = ("creddata", "generated")
DEFAULT_RESULTS = pins.COMMITTED_RESULTS
DEFAULT_DATA_DIR = os.path.join(os.path.expanduser("~"), ".cache", "leftblock-eval")
STATE_FILE = "reproduce-state.json"


def log(message):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), message), flush=True)


def results_paths(results_dir, version):
    return os.path.join(results_dir, version + ".json"), os.path.join(results_dir, version + ".md")


def load_results(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    return None


def write_results(results_dir, results):
    json_path, md_path = results_paths(results_dir, results["leftblock_version"])
    os.makedirs(results_dir, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=1, sort_keys=True)
        handle.write("\n")
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(report.render(results))
    return json_path, md_path


def parse_detectors(text):
    names = []
    for part in text.split(","):
        part = part.strip()
        if part not in ALIASES:
            raise SystemExit("Unknown detector %r; choose from: %s." % (part, ", ".join(ALIASES)))
        names.append(ALIASES[part])
    return names


def require_data_dir(path):
    try:
        return datadir.require_outside_git(path)
    except datadir.DataDirError as exc:
        print(str(exc), file=sys.stderr)
        return None


def evaluate(root, work, results_dir, datasets, selected, seed, deep_sample, smoke_files, shard, allow_mismatch,
             state_path=None, say=log):
    """Run ``datasets`` and write the results. Returns 0, or 2 when gitleaks is the wrong version."""
    from leftblock import cli
    try:
        gitleaks = detectors.gitleaks_state(allow_mismatch, warn=say)
    except detectors.GitleaksMismatch as exc:
        print(str(exc), file=sys.stderr)
        return 2
    version = cli.leftblock_version()
    json_path, _ = results_paths(results_dir, version)
    results = load_results(json_path) or {"datasets": {}}
    deep_used = bool(set(selected) & {detectors.DEEP, detectors.COMBINED})
    arguments = {"seed": seed, "deep_sample": deep_sample, "deep_smoke_files": smoke_files,
                 "detectors": sorted(selected), "datasets": list(datasets)}
    results.update({"leftblock_version": version, "gitleaks_version": gitleaks["version"],
                    "provenance": provenance.collect(version, gitleaks, arguments, deep_used)})
    key = provenance.sha256_of(json.dumps([arguments, pins.MODEL_REVISION, pins.CREDDATA_COMMIT], sort_keys=True).encode())
    state = {"key": key, "datasets": {}}
    if state_path and os.path.exists(state_path):
        previous = load_results(state_path)
        if previous and previous.get("key") == key:
            state = previous
    os.makedirs(work, exist_ok=True)
    for name in datasets:
        say("dataset: %s" % name)
        if name in state["datasets"]:
            say("already finished in an earlier run; reusing it")
            record = state["datasets"][name]
        elif name == "creddata":
            record = runner.run_creddata(root, selected, seed, deep_sample, work, say, shard, smoke_files)
            if shard:
                say("shard %d/%d finished" % shard)
                continue
        else:
            names = [d for d in selected if not (smoke_files and d in (detectors.DEEP, detectors.COMBINED))]
            record = runner.run_generated(root, names, seed, work, say)
        results["datasets"][name] = record
        if state_path:
            state["datasets"][name] = record
            with open(state_path, "w", encoding="utf-8") as handle:
                json.dump(state, handle)
        say("wrote %s and %s" % write_results(results_dir, results))
    return 0


def cmd_fetch(args):
    root = require_data_dir(args.data_dir)
    if root is None:
        return 2
    return creddata.fetch(root, log)


def parse_shard(text, datasets):
    index, _, count = text.partition("/")
    if not (index.isdigit() and count.isdigit() and 0 <= int(index) < int(count)) or list(datasets) != ["creddata"]:
        raise SystemExit("--deep-shard K/N needs 0 <= K < N and --dataset creddata.")
    return int(index), int(count)


def cmd_run(args):
    root = require_data_dir(args.data_dir)
    if root is None:
        return 2
    selected = parse_detectors(args.detectors)
    datasets = [d.strip() for d in args.dataset.split(",")]
    for name in datasets:
        if name not in DATASETS:
            raise SystemExit("Unknown dataset %r; choose from: %s." % (name, ", ".join(DATASETS)))
    shard = parse_shard(args.deep_shard, datasets) if args.deep_shard else None
    return evaluate(root, args.work_dir or os.path.join(root, "work"), args.results_dir, datasets, selected,
                    args.seed, args.deep_sample, args.deep_smoke_files, shard, args.allow_gitleaks_mismatch)


def cmd_check(args):
    root = os.path.realpath(args.data_dir)
    problems, notes = prereq.check(root, args.skip_deep, args.allow_gitleaks_mismatch)
    for note in notes:
        print(note)
    for problem in problems:
        print("MISSING: %s\n    fix: %s" % problem, file=sys.stderr)
    if problems:
        print("%d prerequisite(s) missing." % len(problems), file=sys.stderr)
        return 2
    print("All prerequisites are in place.")
    return 0


def cmd_reproduce(args):
    root = os.path.realpath(args.data_dir)
    problems, notes = prereq.check(root, args.skip_deep, args.allow_gitleaks_mismatch)
    for note in notes:
        log(note)
    if problems:
        for problem in problems:
            print("MISSING: %s\n    fix: %s" % problem, file=sys.stderr)
        print("%d prerequisite(s) missing; nothing was done." % len(problems), file=sys.stderr)
        return 2
    code = creddata.fetch(root, log)
    if code:
        return code
    work = args.work_dir or os.path.join(root, "work")
    results_dir = args.results_dir or os.path.join(root, "results")
    if args.fresh:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    selected = [detectors.STOCK, detectors.LEFTBLOCK] if args.skip_deep else list(detectors.ALL)
    if not args.skip_deep and args.deep_shards > 1:
        log("deep scan: %d shard processes in parallel" % args.deep_shards)
        base = [sys.executable, "-m", "eval", "run", "--dataset", "creddata", "--detectors", "deep", "--data-dir", root,
                "--work-dir", work, "--seed", str(args.seed), "--deep-sample", str(args.deep_sample)]
        if args.deep_smoke_files:
            base += ["--deep-smoke-files", str(args.deep_smoke_files)]
        procs = [subprocess.Popen(base + ["--deep-shard", "%d/%d" % (k, args.deep_shards)], cwd=pins.REPO_ROOT)
                 for k in range(args.deep_shards)]
        if any(p.wait() for p in procs):
            print("A deep-scan shard failed; run the same command again to resume.", file=sys.stderr)
            return 1
    code = evaluate(root, work, results_dir, list(DATASETS), selected, args.seed, args.deep_sample, args.deep_smoke_files,
                    None, args.allow_gitleaks_mismatch, os.path.join(work, STATE_FILE))
    if code:
        return code
    from leftblock import cli
    produced = results_paths(results_dir, cli.leftblock_version())[0]
    log("Done. Compare with the committed results:\n    python -m eval compare %s %s"
        % (os.path.join("eval", "results", os.path.basename(produced)), produced))
    return 0


def cmd_report(args):
    from leftblock import cli
    version = args.version or cli.leftblock_version()
    json_path, _ = results_paths(args.results_dir, version)
    results = load_results(json_path)
    if not results:
        print("No results at %s; run `python -m eval reproduce` first." % json_path, file=sys.stderr)
        return 2
    print("wrote %s and %s" % write_results(args.results_dir, results))
    return 0


def cmd_compare(args):
    try:
        a, b = compare.load(args.a), compare.load(args.b)
    except (OSError, ValueError) as exc:
        print("Cannot read a results file: %s" % exc, file=sys.stderr)
        return 2
    print(compare.render(a, b, args.a, args.b))
    return 0


def add_common(parser):
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                        help="directory outside any Git repository (default %(default)s)")
    parser.add_argument("--allow-gitleaks-mismatch", action="store_true",
                        help="run with a gitleaks other than the pinned one (warns, and records it in the results)")


def build_parser():
    parser = argparse.ArgumentParser(prog="python -m eval", description="LeftBlock detection evaluation")
    sub = parser.add_subparsers(dest="command", required=True)

    rep = sub.add_parser("reproduce", help="check prerequisites, fetch the data, run everything, write results (resumable)")
    add_common(rep)
    rep.add_argument("--skip-deep", action="store_true", help="gitleaks only: no model, no torch, minutes instead of hours")
    rep.add_argument("--deep-shards", type=int, default=1, metavar="N", help="scan with N parallel model processes (default 1)")
    rep.add_argument("--deep-sample", type=int, default=runner.DEFAULT_DEEP_SAMPLE)
    rep.add_argument("--deep-smoke-files", type=int, metavar="N",
                     help="deep scan only N files: a quick pipeline check whose deep numbers are NOT estimates")
    rep.add_argument("--seed", type=int, default=runner.DEFAULT_SEED)
    rep.add_argument("--results-dir", help="default: <data-dir>/results (the committed eval/results is never overwritten by default)")
    rep.add_argument("--work-dir", help="scratch and checkpoints (default: <data-dir>/work)")
    rep.add_argument("--fresh", action="store_true", help="discard checkpoints and start over")
    rep.set_defaults(func=cmd_reproduce)

    chk = sub.add_parser("check", help="check prerequisites and say how to fix what is missing")
    add_common(chk)
    chk.add_argument("--skip-deep", action="store_true")
    chk.set_defaults(func=cmd_check)

    cmp_ = sub.add_parser("compare", help="show two results files side by side (informational; always exits 0)")
    cmp_.add_argument("a")
    cmp_.add_argument("b")
    cmp_.set_defaults(func=cmd_compare)

    fetch = sub.add_parser("fetch", help="download CredData at the pinned commit (about 15 GB of scratch, ~1 GB kept)")
    fetch.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    fetch.set_defaults(func=cmd_fetch)

    run = sub.add_parser("run", help="lower level than reproduce: run detectors over datasets and write <results-dir>/<version>.{json,md}")
    add_common(run)
    run.add_argument("--dataset", default="creddata,generated", help="creddata, generated or both (comma separated)")
    run.add_argument("--detectors", default=",".join(ALIASES), help="comma separated: stock, leftblock, deep, combined")
    run.add_argument("--deep-sample", type=int, default=runner.DEFAULT_DEEP_SAMPLE,
                     help="CredData lines (besides all critical-tier true lines) whose windows the deep scan reads (default %(default)s)")
    run.add_argument("--deep-smoke-files", type=int, metavar="N", help="deep scan only N files (not an estimate)")
    run.add_argument("--seed", type=int, default=runner.DEFAULT_SEED)
    run.add_argument("--results-dir", default=DEFAULT_RESULTS)
    run.add_argument("--work-dir", help="scratch directory (default: <data-dir>/work)")
    run.add_argument("--deep-shard", metavar="K/N",
                     help="CredData only: scan every N-th file with the model (shard K) into the cache and exit")
    run.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="re-render the Markdown report from the results JSON")
    rp.add_argument("--results-dir", default=DEFAULT_RESULTS)
    rp.add_argument("--version", help="LeftBlock version whose results to render (default: installed)")
    rp.set_defaults(func=cmd_report)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
