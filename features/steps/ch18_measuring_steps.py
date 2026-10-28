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
    ], cwd=context.root)
    context.results = None
    for path in glob.glob(os.path.join(context.results_dir, "*.json")):
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
