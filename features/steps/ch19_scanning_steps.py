"""Chapter 19 (scanning text outside git): records, files, and what comes back.

Texts are written with bracketed placeholders such as ``[email]`` or ``[wif]``;
the value behind each is generated at run time (and remembered, so no output
may reveal it). Nothing here is shaped like a secret, an address or a key.
"""

import json
import os
import random
import re
import shutil
import sys

from behave import given, then, when

import synthetic_data
import world
from synthetic_data import ALNUM, LOWER, bad_checksum, token, uuid4, wif

PLACEHOLDER = re.compile(r"\[([a-z][a-z0-9 ]*)\]")


# --- Placeholders -------------------------------------------------------------------

def _email(rng):
    return token(rng, 6, LOWER) + "." + token(rng, 7, LOWER) + "@" + token(rng, 9, LOWER) + ".com"


def _pem(rng):
    body = "\n".join(token(rng, 64, ALNUM) for _ in range(5))
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----"


BUILDERS = {
    "email": _email,
    "wif": wif,
    "bad wif": lambda rng: bad_checksum(wif(rng)),
    "openai key": lambda rng: synthetic_data.make("OpenAI key", rng)[1][0],
    "pem": _pem,
    "uuid": uuid4,
    "digest": lambda rng: token(rng, 40, synthetic_data.HEX),
    "flagged": lambda rng: token(rng, 28, ALNUM),
    "person": lambda rng: token(rng, 1, LOWER.upper()) + token(rng, 6, LOWER) + " " + token(rng, 1, LOWER.upper()) + token(rng, 7, LOWER),
}


def value_of(context, name):
    """The generated value behind ``[name]`` ("email 2" is a second, different email)."""
    if not hasattr(context, "scan_values"):
        context.scan_values = {}
    if name not in context.scan_values:
        builder = BUILDERS[re.sub(r" \d+$", "", name)]
        value = builder(random.Random("scan " + name))
        context.scan_values[name] = value
        context.synthetic_values.append(value)
    return context.scan_values[name]


def fill(context, text):
    return PLACEHOLDER.sub(lambda m: value_of(context, m.group(1)), text)


def unescape(text):
    return text.replace("\\r", "\r").replace("\\n", "\n")


# --- Records ------------------------------------------------------------------------

def _records(context):
    if not hasattr(context, "records"):
        context.records = []
    return context.records


@given('a record "{rid}" with the text:')
def step_record_block(context, rid):
    """A record whose text is the docstring (newlines and any Unicode), placeholders filled."""
    _records(context).append((rid, fill(context, context.text)))


@given('a record "{rid}" with the text "{text}"')
def step_record_inline(context, rid, text):
    """A record whose text is one quoted line; ``\\n`` and ``\\r`` stand for those characters."""
    _records(context).append((rid, fill(context, unescape(text))))


@given('{count:d} clean records and then a record "{rid}" with the text "{text}"')
def step_many_records(context, count, rid, text):
    for number in range(count):
        _records(context).append(("clean-%d" % number, "line %d of an ordinary transcript\nnothing sensitive" % number))
    _records(context).append((rid, fill(context, unescape(text))))


def _scan(context, *args, stdin=None):
    context.result = world.leftblock(context, "scan", *args, stdin=stdin)
    context.was_commit = False
    context.findings = []
    if context.result.returncode in (0, 1) and "--jsonl" in args:
        context.findings = [json.loads(line) for line in context.result.stdout.splitlines()]


def _jsonl(context):
    return "".join(json.dumps({"id": rid, "text": text}) + "\n" for rid, text in _records(context))


@when("I scan the records")
def step_scan_records(context):
    _scan(context, "--jsonl", stdin=_jsonl(context))


@when('I scan the records with "{options}"')
def step_scan_records_with(context, options):
    _scan(context, "--jsonl", *options.split(), stdin=_jsonl(context))


@when("I scan empty input")
def step_scan_empty(context):
    _scan(context, "--jsonl", stdin="")


@when("I scan the raw input:")
def step_scan_raw(context):
    _scan(context, "--jsonl", stdin=fill(context, context.text) + "\n")


# --- Then: findings --------------------------------------------------------------------

@then("the scan reports {count:d} findings")
@then("the scan reports {count:d} finding")
def step_count(context, count):
    assert len(context.findings) == count, "%d findings:\n%s" % (len(context.findings), context.result.stdout)


def _finding(context, number, rid):
    mine = [f for f in context.findings if f["id"] == rid]
    assert len(mine) >= number >= 1, "record %r has %d findings: %r" % (rid, len(mine), mine)
    return mine[number - 1]


def _text(context, rid):
    return next(text for found, text in _records(context) if found == rid)


@then('finding {number:d} of record "{rid}" is for rule "{rule}" of kind "{kind}"')
def step_rule_kind(context, number, rid, rule, kind):
    found = _finding(context, number, rid)
    assert (found["rule"], found["kind"]) == (rule, kind), found


@then('finding {number:d} of record "{rid}" slices to {placeholder}')
def step_slices(context, number, rid, placeholder):
    """The record text, cut at the finding's byte offsets, is exactly the value."""
    found = _finding(context, number, rid)
    data = _text(context, rid).encode("utf-8")
    expected = value_of(context, placeholder.strip("[]"))
    assert data[found["start"]:found["end"]].decode("utf-8") == expected, found


@then('finding {number:d} of record "{rid}" starts at byte {start:d}')
def step_starts(context, number, rid, start):
    assert _finding(context, number, rid)["start"] == start, _finding(context, number, rid)


@then('finding {number:d} of record "{rid}" has score {score:f}')
def step_score(context, number, rid, score):
    assert _finding(context, number, rid)["score"] == score, _finding(context, number, rid)


@then('every finding has exactly the fields "{fields}"')
def step_fields(context, fields):
    wanted = sorted(f.strip() for f in fields.split(","))
    assert context.findings, "no findings"
    for found in context.findings:
        assert sorted(found) == wanted, found


@then("stdout holds nothing but one JSON object per line")
def step_json_lines(context):
    for line in context.result.stdout.splitlines():
        assert isinstance(json.loads(line), dict), line
    assert context.result.stdout == "" or context.result.stdout.endswith("\n")


@then('the ids of the findings in records "{first}" and "{second}" differ')
def step_ids_differ(context, first, second):
    assert _finding(context, 1, first)["finding_id"] != _finding(context, 1, second)["finding_id"]


@then('every finding in record "{rid}" has the same id')
def step_ids_same(context, rid):
    ids = {f["finding_id"] for f in context.findings if f["id"] == rid}
    assert len(ids) == 1, ids


@then("the scan finding id is 16 hexadecimal digits")
def step_id_shape(context):
    assert re.fullmatch(r"[0-9a-f]{16}", context.findings[0]["finding_id"]), context.findings[0]


# --- The hook's ids and overrides ---------------------------------------------------------

@given('a staged file "{name}" with the text:')
def step_staged_filled(context, name):
    world.write_file(context, name, fill(context, context.text) + "\n")
    world.git(context, "add", name)


@when("I note the finding id from a check")
def step_note_check_id(context):
    context.result = world.leftblock(context, "check", "--format", "json")
    assert context.result.returncode == 1, context.result.stderr
    context.noted_id = json.loads(context.result.stdout)["findings"][0]["id"]


@when('I scan a record "{rid}" holding the text of the staged file "{name}"')
def step_scan_staged_text(context, rid, name):
    with open(os.path.join(context.repo, name), encoding="utf-8") as handle:
        _records(context).append((rid, handle.read()))
    _scan(context, "--jsonl", stdin=_jsonl(context))


@when('I record an override for the noted finding because "{reason}"')
def step_override(context, reason):
    context.result = world.leftblock(context, "allow", context.noted_id, "--reason", reason)
    assert context.result.returncode == 0, context.result.stderr
    world.git(context, "add", ".leftblock-allow.yml")


@then("the scan finding id equals the id the check gave")
def step_ids_equal(context):
    assert context.findings[0]["finding_id"] == context.noted_id, (context.findings, context.noted_id)


# --- Temporary files and gitleaks calls ----------------------------------------------------

@given("the temporary directory is a folder of the scenario")
def step_tmpdir(context):
    context.tmp = os.path.join(context.root, "tmp")
    os.makedirs(context.tmp)
    context.env["TMPDIR"] = context.tmp


@then("the temporary directory is empty")
def step_tmp_empty(context):
    assert os.listdir(context.tmp) == [], os.listdir(context.tmp)


def _stand_in(context, source):
    """Put an executable named gitleaks first on PATH; returns the real one."""
    real = shutil.which("gitleaks")
    folder = os.path.join(context.root, "bin")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "gitleaks")
    with open(path, "w") as handle:
        handle.write(source.replace("@PYTHON@", sys.executable).replace("@REAL@", real or ""))
    os.chmod(path, 0o755)
    context.env["PATH"] = folder + os.pathsep + context.env.get("PATH", os.defpath)


@given("gitleaks fails when it is run")
def step_gitleaks_fails(context):
    _stand_in(context, "#!/bin/sh\nexit 3\n")


@given("gitleaks calls are recorded")
def step_gitleaks_recorded(context):
    context.gitleaks_log = os.path.join(context.root, "gitleaks-calls.jsonl")
    _stand_in(context, '''#!@PYTHON@
import json, os, stat, sys
args = sys.argv[1:]
target = args[1] if len(args) > 1 else ""
entry = {"args": args}
if os.path.isdir(target):
    entry["mode"] = stat.S_IMODE(os.stat(os.path.dirname(target)).st_mode)
    entry["files"] = len(os.listdir(target))
with open(%r, "a") as handle:
    handle.write(json.dumps(entry) + "\\n")
os.execv("@REAL@", ["@REAL@"] + args)
''' % context.gitleaks_log)


def _calls(context):
    if not os.path.exists(context.gitleaks_log):
        return []
    with open(context.gitleaks_log) as handle:
        return [json.loads(line) for line in handle]


@then("gitleaks ran once")
def step_ran_once(context):
    assert len(_calls(context)) == 1, _calls(context)


@then("gitleaks was given {count:d} record files in a folder only the owner can enter")
def step_private_folder(context, count):
    call = _calls(context)[0]
    assert call["files"] == count and call["mode"] == 0o700, call


@then("no gitleaks argument holds any record text or value")
def step_no_argv_text(context):
    arguments = [a for call in _calls(context) for a in call["args"]]
    secrets = list(context.synthetic_values) + [text for _, text in _records(context) if len(text) > 8]
    assert arguments and secrets
    for argument in arguments:
        for secret in secrets:
            assert secret not in argument, "a value reached gitleaks' argument list"


# --- Paths -----------------------------------------------------------------------------------

@given('a file "{path}" with the text:')
def step_file(context, path):
    """A file under the scenario folder (no repository), placeholders filled."""
    full = os.path.join(context.root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(fill(context, context.text) + "\n")


@given("a folder that is not inside any Git repository")
def step_not_repository(context):
    probe = world.run(context, ["git", "rev-parse", "--git-dir"], cwd=context.root)
    assert probe.returncode != 0, "the scenario folder is inside a repository"
    context.repo = None


@then('finding {number:d} of the JSON output slices "{path}" to {placeholder}')
def step_json_slices(context, number, path, placeholder):
    found = json.loads(context.result.stdout)["findings"][number - 1]
    with open(os.path.join(context.root, path), "rb") as handle:
        data = handle.read()
    expected = value_of(context, placeholder.strip("[]"))
    assert data[found["start"]:found["end"]].decode("utf-8") == expected, found


@then("the JSON output has {count:d} finding")
def step_json_count(context, count):
    assert len(json.loads(context.result.stdout)["findings"]) == count, context.result.stdout


@then("the JSON output has no findings")
def step_json_empty(context):
    assert json.loads(context.result.stdout) == {"findings": []}, context.result.stdout


# --- The deep scan stub --------------------------------------------------------------------------

@given("the model recognises {placeholder} as {label} at {score:f}")
def step_model_recognises(context, placeholder, label, score):
    assert hasattr(context, "stub_spans"), "replace the model by a stub detector first"
    context.stub_spans.append({"value": value_of(context, placeholder.strip("[]")), "label": label, "score": score})
    with open(context.stub_spans_path, "w") as handle:
        json.dump(context.stub_spans, handle)


@then("nothing is printed on stdout")
def step_stdout_empty(context):
    assert context.result.stdout == "", context.result.stdout
