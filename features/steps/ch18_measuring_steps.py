"""Chapter 18 (measuring detection): a tiny CredData-shaped dataset built at run time.

``a fixture dataset`` creates ``eval-data/CredData/{meta,data}`` in the
scenario's temporary world. ``the fixture labels these lines:`` adds one file
per table row and one label row for it. Shapes (all values built at run time,
nothing sensitive is written in the repository):

- ``ruleset key``: a provider-prefixed key that LeftBlock's shipped rules
  catch and stock gitleaks does not (variable name carries no keyword).
- ``model-only secret``: a random token only the stub model flags.
- ``pem block``: a multi-line private key block (label spans several lines).
- ``quiet value``: nothing detects it.
- ``uuid``: a UUID the LeftBlock ruleset flags on purpose.

The model is replaced by ``features/stub_detector.py``.
"""

import csv
import glob
import json
import os
import random
import re
import shutil
import stat
import sys
import tempfile

from behave import given, then, when

import synthetic_data
import world
from synthetic_data import HEX, token, uuid4

FEATURES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(FEATURES_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

HEADER = ["Id", "FileID", "Domain", "RepoName", "FilePath", "LineStart", "LineEnd", "GroundTruth",
          "ValueStart", "ValueEnd", "CryptographyKey", "PredefinedPattern", "Category"]
REPO = "00fix000"

DETECTORS = {
    "stock gitleaks": "gitleaks-stock",
    "LeftBlock ruleset": "gitleaks-leftblock",
    "deep scan": "deep-scan",
    "combined": "leftblock+deep",
}


# --- Fixture building -----------------------------------------------------------

def _shape(shape, rng):
    """(labelled lines, secret values, model-flagged values)."""
    if shape == "ruleset key":
        value = "fw" + "_" + token(rng, 24)
        return ['ref = "%s"' % value], [value], []
    if shape == "model-only secret":
        value = token(rng, 28)
        return ['build_blob = "%s"' % value], [value], [value]
    if shape == "pem block":
        label = "RSA PRIVATE" + " KEY"
        body = [token(rng, 64, synthetic_data.ALNUM) for _ in range(3)]
        lines = ["-----BEGIN %s-----" % label] + body + ["-----END %s-----" % label]
        return lines, body, []
    if shape == "quiet value":
        return ["build_number = %d" % rng.randint(1000, 9999)], [], []
    if shape == "uuid":
        value = uuid4(rng)
        return ['trace_id = "%s"' % value], [value], []
    raise AssertionError("unknown fixture shape %r" % shape)


def _write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write("\n".join(lines) + "\n")


def _file_id(rng):
    return token(rng, 8, HEX)


@given("a fixture dataset")
def step_fixture_dataset(context):
    context.eval_root = os.path.join(context.root, "eval-data")
    clone = os.path.join(context.eval_root, "CredData")
    os.makedirs(os.path.join(clone, "meta"))
    os.makedirs(os.path.join(clone, "data", REPO))
    context.results_dir = os.path.join(context.root, "eval-results")
    from eval import pins
    with open(os.path.join(clone, ".leftblock-fetch-complete"), "w") as handle:
        json.dump({"commit": pins.CREDDATA_COMMIT}, handle)
    context.strict_gitleaks = False
    context.fixture_rows = []
    context.fixture_values = []
    context.fixture_paths = []
    context.model_values = []
    context.fixture_rng = random.Random("fixture dataset")


@given("the fixture labels these lines:")
def step_fixture_labels(context):
    rng = context.fixture_rng
    clone = os.path.join(context.eval_root, "CredData")
    for row in context.table:
        lines, values, model = _shape(row["shape"], rng)
        file_id = _file_id(rng)
        relative = "data/%s/_/%s.py" % (REPO, file_id)
        _write(os.path.join(clone, relative), ["# fixture file", "import os"] + lines + ["print('done')"])
        context.fixture_rows.append([
            len(context.fixture_rows) + 1, file_id, "GitHub", REPO, relative, 3, 2 + len(lines), row["truth"],
            "", "", "", "", row["category"],
        ])
        context.fixture_values.extend(values)
        context.model_values.extend(model)
        context.fixture_paths.extend([relative, file_id])
    with open(os.path.join(clone, "meta", REPO + ".csv"), "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(context.fixture_rows)


@given("the fixture also holds an unlabelled file with a ruleset key")
def step_fixture_unlabelled(context):
    lines, values, _ = _shape("ruleset key", context.fixture_rng)
    clone = os.path.join(context.eval_root, "CredData")
    relative = "data/%s/_/%s.py" % (REPO, _file_id(context.fixture_rng))
    _write(os.path.join(clone, relative), ["# unlabelled file"] + lines)
    context.fixture_values.extend(values)
    context.fixture_paths.append(relative)


@given("the model flags the fixture's model-only secrets as secret at {score}")
def step_model_flags(context, score):
    context.stub_spans = [{"value": v, "label": "secret", "score": float(score)} for v in context.model_values]


def _stub_environment(context):
    spans = os.path.join(context.root, "stub-spans.json")
    with open(spans, "w") as handle:
        json.dump(getattr(context, "stub_spans", []), handle)
    context.env["PYTHONPATH"] = os.pathsep.join([PROJECT_ROOT, FEATURES_DIR])
    context.env["LEFTBLOCK_DEEP_DETECTOR"] = "stub_detector:factory"
    context.env["LEFTBLOCK_STUB_SPANS"] = spans


# --- When -------------------------------------------------------------------------

def _evaluate(context, dataset, names, sample=100, data_dir=None):
    _stub_environment(context)
    context.results_dir = getattr(context, "results_dir", os.path.join(context.root, "eval-results"))
    context.result = world.run(context, [
        sys.executable, "-m", "eval", "run", "--dataset", dataset, "--detectors", names,
        "--data-dir", data_dir or context.eval_root, "--results-dir", context.results_dir,
        "--deep-sample", str(sample),
    ] + ([] if getattr(context, "strict_gitleaks", False) else ["--allow-gitleaks-mismatch"]), cwd=context.root)
    _load_results(context, context.results_dir)


def _load_results(context, directory):
    context.results = None
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path) as handle:
            context.results = json.load(handle)
        context.report_json = path
        context.report_md = path[:-len(".json")] + ".md"


@when('I evaluate the fixture with detectors "{names}"')
def step_evaluate(context, names):
    _evaluate(context, "creddata", names)


@when('I evaluate the fixture with detectors "{names}" and a deep sample of {sample:d}')
def step_evaluate_sample(context, names, sample):
    _evaluate(context, "creddata", names, sample)


@when('I evaluate the generated corpus with detectors "{names}"')
def step_evaluate_generated(context, names):
    _evaluate(context, "generated", names)


@when("I evaluate with the data directory inside that repository")
def step_evaluate_inside_repository(context):
    _evaluate(context, "creddata", "leftblock", data_dir=context.repo)


# --- Then -------------------------------------------------------------------------

def _record(context):
    return context.results["datasets"]["creddata"]


def _section(context, scope):
    record = _record(context)
    if scope == "full files":
        return record["full_files"]
    if scope == "deep sample":
        return record["windows"]
    raise AssertionError("unknown scope %r" % scope)


@then("the evaluation succeeds")
def step_evaluation_succeeds(context):
    assert context.result.returncode == 0, "evaluation failed:\n" + world.output(context)
    assert context.results, "no results file was written"


@then('in the {scope} "{detector}" scores {tp:d} true positives, {fp:d} false positives and {fn:d} misses')
def step_scores(context, scope, detector, tp, fp, fn):
    counts = _section(context, scope)["detectors"][DETECTORS[detector]]["overall"]["counts"]
    assert (counts["tp"], counts["fp"], counts["fn"]) == (tp, fp, fn), counts


@then('in the {scope} "{detector}" has recall {recall} and precision {precision}')
def step_rates(context, scope, detector, recall, precision):
    overall = _section(context, scope)["detectors"][DETECTORS[detector]]["overall"]
    got = ("%.1f%%" % (100 * overall["recall"]["value"]), "%.1f%%" % (100 * overall["precision"]["value"]))
    assert got == (recall, precision), got


@then('in the {scope} the critical tier holds {total:d} true lines and "{detector}" misses {missed:d} of them')
def step_critical(context, scope, total, detector, missed):
    counts = _section(context, scope)["detectors"][DETECTORS[detector]]["critical"]["counts"]
    assert (counts["tp"] + counts["fn"], counts["fn"]) == (total, missed), counts


@then("{count:d} labelled lines are excluded as X")
def step_excluded(context, count):
    assert _record(context)["units"]["excluded_x_lines"] == count, _record(context)["units"]


@then('{count:d} findings on unlabelled lines are reported for "{detector}" apart from the scores')
def step_unlabelled(context, count, detector):
    assert _record(context)["unlabelled_flags"][DETECTORS[detector]]["findings"] == count


@then("the deep scan adds {tp:d} true positives and {fp:d} false positives over the LeftBlock ruleset")
def step_deep_adds(context, tp, fp):
    adds = _record(context)["windows"]["adds"]["deep-scan_over_gitleaks-leftblock"]
    assert (adds["new_true_positives"]["count"], adds["new_false_positives"]["count"]) == (tp, fp), adds


@then("the deep sample holds {count:d} critical true lines")
def step_sample_census(context, count):
    assert _record(context)["windows"]["sample"]["critical_true_census"] == count


@then("the deep sample estimates {estimated:d} false lines from {sampled:d} sampled")
def step_sample_weights(context, estimated, sampled):
    overall = _record(context)["windows"]["detectors"]["gitleaks-leftblock"]["overall"]
    assert overall["counts"]["fp"] + overall["counts"]["tn"] == sampled, overall
    assert round(overall["estimated"]["fp"] + overall["estimated"]["tn"]) == estimated, overall


def _rates(node):
    if isinstance(node, dict):
        if {"value", "lo", "hi"} <= set(node):
            yield node
        for child in node.values():
            for found in _rates(child):
                yield found
    elif isinstance(node, list):
        for child in node:
            for found in _rates(child):
                yield found


@then("every reported rate has a 95% interval around it")
def step_intervals(context):
    rates = [r for r in _rates(context.results) if r["value"] is not None]
    assert rates, "no rates reported"
    for r in rates:
        assert 0.0 <= r["lo"] <= r["value"] <= r["hi"] <= 1.0, r
        assert r["lo"] < r["hi"], r


def _report_text(context):
    with open(context.report_json) as handle:
        raw = handle.read()
    with open(context.report_md) as handle:
        return raw + handle.read()


@then("the report reveals no fixture value or file path")
def step_no_values(context):
    text = _report_text(context)
    assert context.fixture_values, "the scenario planted no values"
    for secret in context.fixture_values + context.fixture_paths:
        assert secret not in text, "the report repeats a fixture value or path"


@then("the report states the critical tier and the excluded count")
def step_states_tier(context):
    with open(context.report_md) as handle:
        text = handle.read()
    assert "Critical tier" in text and "lines labelled X were excluded" in text


@then("the generated corpus had more than {count:d} labelled lines")
def step_generated_size(context, count):
    assert context.results["datasets"]["generated"]["units"]["labelled_lines"] > count


@then("the generated corpus left no files behind")
def step_generated_cleanup(context):
    work = os.path.join(context.eval_root, "work")
    assert not os.path.exists(os.path.join(work, "corpus")), "corpus directory still exists"


@then("the report reveals no generated value")
def step_no_generated_values(context):
    from eval import generated
    text = _report_text(context)
    seed = context.results["datasets"]["generated"]["seed"]
    with tempfile.TemporaryDirectory() as scratch:
        generated.generate(scratch, seed)
        long_tokens = set()
        for base, _, names in os.walk(scratch):
            for name in names:
                with open(os.path.join(base, name)) as handle:
                    long_tokens.update(re.findall(r"[A-Za-z0-9+/_\-.]{20,}", handle.read()))
    assert len(long_tokens) > 100
    leaked = [t for t in long_tokens if t in text]
    assert not leaked, "%d generated tokens appear in the report" % len(leaked)


# --- Running it from a fresh clone ---------------------------------------------------

PINNED = "8.30.1"


def _bin_dir(context):
    path = os.path.join(context.root, "stub-bin")
    os.makedirs(path, exist_ok=True)
    return path


def _only_git_on_path(context):
    bin_dir = _bin_dir(context)
    if not os.path.exists(os.path.join(bin_dir, "git")):
        os.symlink(shutil.which("git"), os.path.join(bin_dir, "git"))
    return bin_dir


def _gitleaks_wrapper(context, version):
    """A ``gitleaks`` that reports ``version`` and otherwise runs the real one (if any)."""
    real = shutil.which("gitleaks") or "/bin/false"
    path = os.path.join(_bin_dir(context), "gitleaks")
    with open(path, "w") as handle:
        handle.write('#!/bin/sh\nif [ "$1" = "version" ]; then echo %s; exit 0; fi\nexec "%s" "$@"\n' % (version, real))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    context.env["PATH"] = _bin_dir(context) + os.pathsep + context.env["PATH"]


@given("gitleaks is not installed")
def step_no_gitleaks(context):
    context.env["PATH"] = _only_git_on_path(context)


@given("gitleaks at the pinned version")
def step_pinned_gitleaks(context):
    _gitleaks_wrapper(context, PINNED)


@given("gitleaks reporting version {version}")
def step_other_gitleaks(context, version):
    _gitleaks_wrapper(context, version)


@given("the fixture download did not finish")
def step_unfinished_download(context):
    os.remove(os.path.join(context.eval_root, "CredData", ".leftblock-fetch-complete"))


@given("the model is interrupted after {count:d} calls")
def step_interrupted(context, count):
    context.stub_log = os.path.join(context.root, "stub-calls.log")
    context.interrupt_after = count


def _eval(context, *args):
    _stub_environment(context)
    if getattr(context, "stub_log", None):
        context.env["LEFTBLOCK_STUB_LOG"] = context.stub_log
    context.result = world.run(context, [sys.executable, "-m", "eval"] + list(args), cwd=PROJECT_ROOT)


def _calls(context):
    log = getattr(context, "stub_log", None)
    return len(open(log).read().split()) if log and os.path.exists(log) else 0


@when("I check the evaluation prerequisites without the deep scan")
def step_check_shallow(context):
    _eval(context, "check", "--skip-deep", "--data-dir", context.eval_root)


@when("I check the evaluation prerequisites with the deep scan")
def step_check_deep(context):
    _eval(context, "check", "--data-dir", context.eval_root)


@when('I evaluate the fixture with detectors "{names}" and no mismatch allowance')
def step_evaluate_strict(context, names):
    context.strict_gitleaks = True
    _evaluate(context, "creddata", names)


def _reproduce(context, *extra):
    context.reproduced_dir = os.path.join(context.eval_root, "results")
    if getattr(context, "interrupt_after", None) is not None and not getattr(context, "interruption_over", False):
        context.env["LEFTBLOCK_STUB_FAIL_AFTER"] = str(context.interrupt_after)
    else:
        context.env.pop("LEFTBLOCK_STUB_FAIL_AFTER", None)
    _eval(context, "reproduce", "--data-dir", context.eval_root, "--allow-gitleaks-mismatch", *extra)
    _load_results(context, context.reproduced_dir)


@when("I reproduce the evaluation without the deep scan")
def step_reproduce_shallow(context):
    _reproduce(context, "--skip-deep")


@when("I reproduce the evaluation with a deep smoke run on {count:d} files")
def step_reproduce_smoke(context, count):
    _reproduce(context, "--deep-smoke-files", str(count))


@when("the interruption is over and I reproduce again")
def step_reproduce_again(context):
    context.calls_before = _calls(context)
    context.interruption_over = True
    _reproduce(context, "--deep-smoke-files", "4")


@when("I compare the results with themselves")
def step_compare_self(context):
    _eval(context, "compare", context.report_json, context.report_json)


@when("I compare the results with a copy whose LeftBlock recall and gitleaks version are changed")
def step_compare_changed(context):
    changed = json.loads(json.dumps(context.results))
    changed["datasets"]["creddata"]["full_files"]["detectors"]["gitleaks-leftblock"]["overall"]["recall"]["value"] = 0.123
    changed["provenance"]["gitleaks"]["version"] = "9.9.9"
    other = os.path.join(context.root, "changed.json")
    with open(other, "w") as handle:
        json.dump(changed, handle)
    _eval(context, "compare", context.report_json, other)


@when("I compare two results files that do not exist")
def step_compare_missing(context):
    _eval(context, "compare", os.path.join(context.root, "no-a.json"), os.path.join(context.root, "no-b.json"))


@then("the exit code is not 0")
def step_exit_nonzero(context):
    assert context.result.returncode != 0, world.output(context)


@then("no results were written")
def step_no_results(context):
    for directory in (context.results_dir, os.path.join(context.eval_root, "results")):
        assert not glob.glob(os.path.join(directory, "*.json")), "results were written to " + directory


@then("the results record gitleaks {version} as not matching the pin")
def step_records_mismatch(context, version):
    state = context.results["provenance"]["gitleaks"]
    assert (state["version"], state["pinned"], state["matches_pin"]) == (version, PINNED, False), state


@then("the results record the gitleaks version and the pinned one")
def step_records_gitleaks(context):
    state = context.results["provenance"]["gitleaks"]
    assert state["version"] and state["pinned"] == PINNED, state
    assert context.results["gitleaks_version"] == state["version"]


@then("the results record the CredData commit and digests of its labels and files")
def step_records_creddata(context):
    from eval import pins
    inputs = context.results["datasets"]["creddata"]["inputs"]
    assert inputs["commit"] == pins.CREDDATA_COMMIT, inputs
    for key in ("labels_sha256", "data_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", inputs[key]), inputs


@then("the results record the tier definition and the ruleset digests")
def step_records_tiers(context):
    block = context.results["provenance"]["eval"]
    for key in ("tiers_sha256", "ruleset_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", block[key]), block


@then("the results record the seed and the deep sample size")
def step_records_seed(context):
    arguments = context.results["provenance"]["arguments"]
    assert arguments["seed"] == context.results["datasets"]["creddata"]["seed"]
    assert arguments["deep_sample"] == 100, arguments


@then("the results record the deep-scan model at its pinned revision")
def step_records_model(context):
    from eval import pins
    deep = context.results["provenance"]["deep_scan"]
    assert (deep["model"], deep["revision"]) == (pins.MODEL_ID, pins.MODEL_REVISION), deep
    assert deep["threshold"] == 0.9 and "secret" in deep["labels"], deep


@then("the report lists these inputs in a provenance section")
def step_report_provenance(context):
    with open(context.report_md) as handle:
        text = handle.read()
    for needle in ("## Provenance", "gitleaks", "CredData commit", "Tier definition SHA-256", "Deep-scan model"):
        assert needle in text, needle


@then("the reproduced results hold both datasets")
def step_reproduced_both(context):
    assert context.results, "no results in " + context.reproduced_dir
    assert sorted(context.results["datasets"]) == ["creddata", "generated"]


@then("the reproduced deep sample reads {count:d} files and is marked as a smoke run")
def step_reproduced_smoke(context, count):
    sample = context.results["datasets"]["creddata"]["windows"]["sample"]
    assert sample["files"] == count and sample["smoke_files"] == count, sample
    with open(context.report_md) as handle:
        assert "SMOKE RUN" in handle.read()


@then("the reproduced generated corpus is scored without the deep scan")
def step_reproduced_generated_shallow(context):
    names = sorted(context.results["datasets"]["generated"]["full_files"]["detectors"])
    assert names == ["gitleaks-leftblock", "gitleaks-stock"], names


@then("the model was consulted for {count:d} more calls")
def step_more_calls(context, count):
    assert _calls(context) - context.calls_before == count, (_calls(context), context.calls_before)


@then("the reproduced deep scan scores {count:d} true positives")
def step_reproduced_tp(context, count):
    counts = context.results["datasets"]["creddata"]["windows"]["detectors"]["deep-scan"]["overall"]["counts"]
    assert counts["tp"] == count, counts
