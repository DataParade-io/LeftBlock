"""Chapter 17 (deep scan): a stub detector instead of the real model.

The specs never download the Privacy Filter. ``LEFTBLOCK_DEEP_DETECTOR`` names
``features/stub_detector.py``, which "recognises" the synthetic values these
steps register, each with a label and a score. Values are built at run time.
"""

import json
import os
import random
import re

import yaml
from behave import given, then, when

import synthetic_data
import world
from synthetic_data import ALNUM, HEX, LOWER, token, uuid4, generator

FINDING = re.compile(
    r"^      (?P<file>\S+?):(?P<line>\d+): (?P<rule>\S+) \[id (?P<id>[0-9a-f]{16})\] \(score (?P<score>[0-9.]+)\)$",
    re.MULTILINE,
)
FEATURES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANSI = re.compile("\x1b\\[")
SKIP_WORDS = ["placeholder", "example", "fake", "synthetic", "dummy"]


# --- Synthetic kinds (content the model will be told is sensitive) ------------

def _single(kind, build, template):
    def fn(rng):
        value = build(rng)
        return template % value, [value]
    generator(kind)(fn)


def _email(domain):
    return lambda rng: token(rng, 6, LOWER) + "." + token(rng, 6, LOWER) + "@" + domain(rng)


def _word(rng, n=7):
    return token(rng, 1, LOWER.upper()) + token(rng, n, LOWER)


_single("credential-shaped value", lambda r: token(r, 28, ALNUM), 'service_token = "%s"\n')
for _w in SKIP_WORDS:
    _single(_w + "-marked credential", lambda r: token(r, 28, ALNUM), _w + '_token = "%s"\n')
_single("UUID-shaped value", uuid4, 'build_ref = "%s"\n')
_single("hex digest value", lambda r: token(r, 40, HEX), 'build_hash = "%s"\n')
_single("hex colour value", lambda r: "#" + token(r, 6, HEX), 'accent = "%s"\n')
_single("ISO timestamp value",
        lambda r: "20%s-%s-%sT%s:%s:%sZ" % tuple(token(r, 2, "0123456789") for _ in range(6)),
        'built_at = "%s"\n')
_single("issue id value", lambda r: "ISS-" + token(r, 6, HEX), 'ticket = "%s"\n')
_single("work email", _email(lambda r: token(r, 8, LOWER) + ".co"), 'owner_contact = "%s"\n')
_single("reserved-domain email", _email(lambda r: token(r, 8, LOWER) + ".test"), 'owner_contact = "%s"\n')
_single("noreply email", lambda r: "no" + "reply@" + token(r, 8, LOWER) + ".co", 'sender = "%s"\n')
_single("internal email", _email(lambda r: token(r, 8, LOWER) + ".internal"), 'owner_contact = "%s"\n')
_single("phone number", lambda r: "+1 " + token(r, 3, "0123456789") + " " + token(r, 7, "0123456789"), 'phone = "%s"\n')
_single("street address",
        lambda r: token(r, 3, "123456789") + " " + _word(r) + " Street, " + _word(r),
        'ship_to = "%s"\n')
_single("person name", lambda r: _word(r) + " " + _word(r), 'owner = "%s"\n')
_single("account number", lambda r: token(r, 12, "0123456789"), 'account = "%s"\n')
_single("birth date", lambda r: "19%s-%s-%s" % tuple(token(r, 2, "123456789") for _ in range(3)), 'born = "%s"\n')
_single("profile link", lambda r: "https://" + token(r, 8, LOWER) + ".co/u/" + token(r, 8, LOWER), 'profile = "%s"\n')


# --- Given ---------------------------------------------------------------------

def _stub_env(context):
    context.stub_spans_path = os.path.join(context.root, "stub-spans.json")
    context.stub_log = os.path.join(context.root, "stub-calls.log")
    context.stub_spans = []
    context.env["PYTHONPATH"] = os.pathsep.join([context.env["PYTHONPATH"], FEATURES_DIR])
    context.env["LEFTBLOCK_DEEP_DETECTOR"] = "stub_detector:factory"
    context.env["LEFTBLOCK_STUB_SPANS"] = context.stub_spans_path
    context.env["LEFTBLOCK_STUB_LOG"] = context.stub_log


@given("the deep scan model is replaced by a stub detector")
def step_stub(context):
    """Point the deep scan at features/stub_detector.py instead of the model."""
    _stub_env(context)


@given("the deep scan extra is not installed")
def step_missing_extra(context):
    """Make loading the detector fail as a missing optional extra does."""
    _stub_env(context)
    context.env["LEFTBLOCK_STUB_MISSING_EXTRA"] = "1"


@given('a staged file "{name}" containing a {kind} that the model flags as {label} at {score:f}')
def step_staged_flagged(context, name, kind, label, score):
    """Write a generated ``kind`` into ``name``, stage it and tell the stub to flag it."""
    content, values = synthetic_data.make(kind, random.Random(kind))
    context.synthetic_values.extend(values)
    for value in values:
        context.stub_spans.append({"value": value, "label": label, "score": score})
    with open(context.stub_spans_path, "w") as handle:
        json.dump(context.stub_spans, handle)
    world.write_file(context, name, content)
    world.git(context, "add", name)


@given('the file "{name}" is deleted and committed')
def step_deleted_committed(context, name):
    world.git(context, "rm", "-q", name)
    world.git(context, "commit", "-q", "--no-verify", "-m", "chore: remove " + name)


# --- When ----------------------------------------------------------------------

@when("I note the finding ids from a deep scan")
def step_note_deep_ids(context):
    context.result = world.leftblock(context, "deep-scan")
    assert context.result.returncode == 1, context.result.stderr
    context.noted_ids = [m.group("id") for m in FINDING.finditer(context.result.stderr)]
    assert context.noted_ids, "no finding ids shown:\n" + context.result.stderr


@when('I record a deep scan override for the noted findings because "{reason}"')
def step_record_deep(context, reason):
    context.result = world.leftblock(
        context, "allow", "--deep", *context.noted_ids, "--reason", reason)


@when('the flagged line in "{name}" is reworded and staged')
def step_reword(context, name):
    path = os.path.join(context.repo, name)
    with open(path) as handle:
        text = handle.read()
    with open(path, "w") as handle:
        handle.write("reworded_" + text)
    world.git(context, "add", name)


# --- Then ----------------------------------------------------------------------

def _findings(context):
    return [m.groupdict() for m in FINDING.finditer(context.result.stderr)]


@then('a finding is reported at "{name}" line {line:d} for rule "{rule}" with score {score}')
def step_finding_at(context, name, line, rule, score):
    expected = {"file": name, "line": str(line), "rule": rule, "score": score}
    found = [{k: f[k] for k in expected} for f in _findings(context)]
    assert expected in found, "not reported: %r in %r\n%s" % (expected, found, context.result.stderr)


@then("no finding is reported")
def step_no_finding(context):
    assert not _findings(context), "unexpected findings:\n" + context.result.stderr


@then("{count:d} findings are reported")
def step_finding_count(context, count):
    assert len(_findings(context)) == count, context.result.stderr


@then("the model was never consulted")
def step_model_unused(context):
    assert not os.path.exists(context.stub_log), "the model was consulted"


@then("the model was consulted")
def step_model_used(context):
    assert os.path.exists(context.stub_log), "the model was never consulted"


@then("the output has no ANSI escape codes")
def step_no_ansi(context):
    assert not ANSI.search(world.output(context)), repr(world.output(context))


@then('the staged allow file records rule "{rule}" for "{name}"')
def step_allow_records(context, rule, name):
    text = world.git(context, "show", ":.leftblock-allow.yml").stdout
    entries = yaml.safe_load(text)["allow"]
    assert any(e["rule"] == rule and e["file"] == name for e in entries), text
