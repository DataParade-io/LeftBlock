"""Steps for chapter 20 (receipts for a local CI run).

The GitHub CLI is never called for real: a stand-in ``gh`` placed first on
PATH appends its arguments, one per line, to a log inside the scenario's
world, and can be told to fail.
"""

import hashlib
import hmac
import json
import os
import stat

from behave import given, then

import world

CI_RAN_MARKER = "ci-ran"
STAND_IN_RECORDING = """#!/bin/sh
for argument in "$@"; do printf '%s\\n' "$argument" >> "$GH_STAND_IN_LOG"; done
printf -- '--end-of-call--\\n' >> "$GH_STAND_IN_LOG"
exit "${GH_STAND_IN_EXIT:-0}"
"""


def _policy(command, signing):
    lines = ["ci:", "  command: " + json.dumps(command)]
    if signing:
        lines.append("  sign: true")
    return "\n".join(lines) + "\n"


def _commit_policy(context, command, signing):
    world.make_repository(context)
    world.write_file(context, ".leftblock.yml", _policy(command, signing))
    world.git(context, "add", ".leftblock.yml")
    world.git(context, "commit", "-q", "--no-verify", "-m", "chore: add the CI policy")


def _receipt(context):
    sha = world.head(context)
    path = os.path.join(context.repo, ".git", "leftblock", "receipts", sha + ".json")
    assert os.path.exists(path), "no receipt at " + path
    with open(path) as handle:
        return json.load(handle)


def _posted_calls(context):
    log = os.path.join(context.root, "gh-calls.log")
    if not os.path.exists(log):
        return []
    with open(log) as handle:
        blocks = handle.read().split("--end-of-call--\n")
    return [[line for line in block.split("\n") if line] for block in blocks if block.strip()]


def _posted_field(context, name):
    calls = _posted_calls(context)
    assert len(calls) == 1, "expected one gh call, saw %d" % len(calls)
    prefix = name + "="
    for argument in calls[0]:
        if argument.startswith(prefix):
            return argument[len(prefix):]
    raise AssertionError("gh was not given " + prefix)


@given('a repository whose committed policy runs the CI command "{command}"')
def step_policy(context, command):
    _commit_policy(context, command, signing=False)


@given('a repository whose committed policy runs the CI command "{command}" with signing on')
def step_policy_signing(context, command):
    _commit_policy(context, command, signing=True)


@given("a LeftBlock signing secret exists")
def step_secret(context):
    os.makedirs(os.path.dirname(context.secret_path), exist_ok=True)
    with open(context.secret_path, "w") as handle:
        handle.write("spec-shared-secret\n")


def _install_stand_in(context, exit_code):
    directory = os.path.join(context.root, "stand-in-bin")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "gh")
    with open(path, "w") as handle:
        handle.write(STAND_IN_RECORDING)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    context.env["PATH"] = directory + os.pathsep + context.env["PATH"]
    context.env["GH_STAND_IN_LOG"] = os.path.join(context.root, "gh-calls.log")
    context.env["GH_STAND_IN_EXIT"] = str(exit_code)


@given("the GitHub CLI is replaced by a recording stand-in")
def step_gh_recording(context):
    _install_stand_in(context, 0)


@given("the GitHub CLI is replaced by a stand-in that refuses")
def step_gh_refusing(context):
    _install_stand_in(context, 1)


@given('an uncommitted change to "{name}"')
def step_uncommitted(context, name):
    world.write_file(context, name, "work in progress\n")


@given("a second commit is made")
def step_second_commit(context):
    world.git(context, "commit", "-q", "--allow-empty", "-m", "second commit")


@then('the receipt for HEAD says the result is "{result}"')
def step_receipt_result(context, result):
    assert _receipt(context)["result"] == result, _receipt(context)


@then("the receipt for HEAD records the exact commit and tree")
def step_receipt_identity(context):
    receipt = _receipt(context)
    assert receipt["sha"] == world.head(context)
    tree = world.git(context, "rev-parse", "HEAD^{tree}").stdout.strip()
    assert receipt["tree"] == tree


@then('the receipt for HEAD records one check "{command}" with exit code {code:d}')
def step_receipt_check(context, command, code):
    checks = _receipt(context)["checks"]
    assert len(checks) == 1, checks
    assert checks[0]["command"] == command and checks[0]["exit_code"] == code, checks
    assert checks[0]["duration_s"] >= 0


@then("the receipt for HEAD names the tool versions, the host and the finish time")
def step_receipt_environment(context):
    receipt = _receipt(context)
    assert set(receipt["tools"]) >= {"node", "python3", "git", "leftblock"}, receipt["tools"]
    assert receipt["tools"]["git"], receipt["tools"]
    assert receipt["host"] and receipt["leftblock_version"]
    assert receipt["started_at"].endswith("Z") and receipt["finished_at"].endswith("Z")


@then("the receipt for HEAD has no signature")
def step_receipt_unsigned(context):
    assert "signature" not in _receipt(context)


@then("the receipt for HEAD has a valid signature over sha, tree, result and finish time")
def step_receipt_signed(context):
    receipt = _receipt(context)
    message = "|".join([receipt["sha"], receipt["tree"], receipt["result"], receipt["finished_at"]])
    expected = hmac.new(b"spec-shared-secret", message.encode(), hashlib.sha256).hexdigest()
    assert receipt["signature"] == "hmac-sha256:" + expected, receipt["signature"]


@then("there is no receipt for HEAD")
def step_no_receipt(context):
    path = os.path.join(context.repo, ".git", "leftblock", "receipts", world.head(context) + ".json")
    assert not os.path.exists(path), "unexpected receipt " + path


@then('the commit status posted for HEAD has state "{state}" and context "{status_context}"')
def step_status(context, state, status_context):
    calls = _posted_calls(context)
    assert len(calls) == 1, calls
    assert "repos/{owner}/{repo}/statuses/" + world.head(context) in calls[0], calls[0]
    assert _posted_field(context, "state") == state
    assert _posted_field(context, "context") == status_context


@then('the posted status description starts with "{text}"')
def step_description_start(context, text):
    assert _posted_field(context, "description").startswith(text), _posted_field(context, "description")


@then("the posted status description ends with the first 12 hex digits of the signature")
def step_description_signature(context):
    digits = _receipt(context)["signature"].split(":")[1][:12]
    assert _posted_field(context, "description").endswith(" sig:" + digits)


@then("no commit status was posted")
def step_no_status(context):
    assert _posted_calls(context) == [], _posted_calls(context)


@then("the CI command did not run")
def step_command_did_not_run(context):
    assert not os.path.exists(os.path.join(context.repo, CI_RAN_MARKER))
