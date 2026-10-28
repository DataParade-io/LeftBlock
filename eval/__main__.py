"""``python -m eval``: fetch CredData, run the evaluation, render the report."""

import argparse
import json
import os
import sys
import time

from eval import creddata, datadir, detectors, report, runner

ALIASES = {"stock": detectors.STOCK, "leftblock": detectors.LEFTBLOCK, "deep": detectors.DEEP, "combined": detectors.COMBINED}
DATASETS = ("creddata", "generated")
DEFAULT_RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


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


def cmd_fetch(args):
    try:
        root = datadir.require_outside_git(args.data_dir)
    except datadir.DataDirError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return creddata.fetch(root, log)


def cmd_run(args):
    try:
        root = datadir.require_outside_git(args.data_dir)
    except datadir.DataDirError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    from leftblock import cli
    selected = parse_detectors(args.detectors)
    datasets = [d.strip() for d in args.dataset.split(",")]
    for name in datasets:
        if name not in DATASETS:
            raise SystemExit("Unknown dataset %r; choose from: %s." % (name, ", ".join(DATASETS)))
    version = cli.leftblock_version()
    json_path, _ = results_paths(args.results_dir, version)
    results = load_results(json_path) or {"datasets": {}}
    results.update({"leftblock_version": version, "gitleaks_version": detectors.gitleaks_version()})
    work = args.work_dir or os.path.join(root, "work")
    os.makedirs(work, exist_ok=True)
    for name in datasets:
        log("dataset: %s" % name)
        if name == "creddata":
            record = runner.run_creddata(root, selected, args.seed, args.deep_sample, work, log)
        else:
            record = runner.run_generated(root, selected, args.seed, work, log)
        results["datasets"][name] = record
        paths = write_results(args.results_dir, results)
        log("wrote %s and %s" % paths)
    return 0


def cmd_report(args):
    from leftblock import cli
    version = args.version or cli.leftblock_version()
    json_path, _ = results_paths(args.results_dir, version)
    results = load_results(json_path)
    if not results:
        print("No results at %s; run `python -m eval run` first." % json_path, file=sys.stderr)
        return 2
    print("wrote %s and %s" % write_results(args.results_dir, results))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python -m eval", description="LeftBlock detection evaluation")
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="download CredData at the pinned commit (needs about 30 GB free, ~1 GB kept)")
    fetch.add_argument("--data-dir", required=True, help="directory outside any Git repository")
    fetch.set_defaults(func=cmd_fetch)

    run = sub.add_parser("run", help="run detectors over a dataset and write eval/results/<version>.{json,md}")
    run.add_argument("--dataset", default="creddata,generated", help="creddata, generated or both (comma separated)")
    run.add_argument("--detectors", default=",".join(ALIASES), help="comma separated: stock, leftblock, deep, combined")
    run.add_argument("--data-dir", required=True, help="directory outside any Git repository (holds CredData and scratch files)")
    run.add_argument("--deep-sample", type=int, default=runner.DEFAULT_DEEP_SAMPLE,
                     help="CredData lines (besides all critical-tier true lines) whose windows the deep scan reads (default %(default)s)")
    run.add_argument("--seed", type=int, default=runner.DEFAULT_SEED)
    run.add_argument("--results-dir", default=DEFAULT_RESULTS)
    run.add_argument("--work-dir", help="scratch directory (default: <data-dir>/work)")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", help="re-render the Markdown report from the results JSON")
    rep.add_argument("--results-dir", default=DEFAULT_RESULTS)
    rep.add_argument("--version", help="LeftBlock version whose results to render (default: installed)")
    rep.set_defaults(func=cmd_report)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
