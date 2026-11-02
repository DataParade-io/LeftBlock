"""Chapter 21 (the model in the commit gate): settings, the resident server and its socket.

The model is the chapter 17 stub detector, which runs inside the real server
process and socket. Each scenario gets a private runtime directory under its
temporary root, and features/environment.py stops any server it started.
"""

import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

from behave import given, step, then, when

import world

SERVER_PID = re.compile(r"pid (\d+)")
SERVER_START = re.compile(r"start pid \d+")


def _run_directory(context):
    return os.path.join(context.root, "rt", "leftblock")


def _server_files(context, pattern):
    return glob.glob(os.path.join(_run_directory(context), pattern))


def _server_running(context):
    return world.leftblock(context, "deep-server", "status").returncode == 0


# --- Given --------------------------------------------------------------------------

@given("the Privacy Filter server uses a private runtime directory")
def step_runtime_directory(context):
    """Point XDG_RUNTIME_DIR at a directory under the scenario's temporary root."""
    base = os.path.join(context.root, "rt")
    os.makedirs(base)
    context.env["XDG_RUNTIME_DIR"] = base


@given('the repository sets "{key}" to "{value}"')
def step_repository_setting(context, key, value):
    world.git(context, "config", key, value)


@given('the global Git config sets "{key}" to "{value}"')
def step_global_setting(context, key, value):
    context.env["GIT_CONFIG_GLOBAL"] = os.path.join(context.root, "global-gitconfig")
    world.git(context, "config", "--global", key, value)


@given("the model weights are not downloaded")
def step_weights_missing(context):
    context.env["LEFTBLOCK_STUB_MODEL_MISSING"] = "1"


@given("the server directory is open to other users")
def step_open_directory(context):
    os.makedirs(_run_directory(context))
    os.chmod(_run_directory(context), 0o755)


@given("the model is told to flag the synthetic values so far as {label} at {score:f}")
def step_flag_synthetic_values(context, label, score):
    context.stub_spans = [
        {"value": value, "label": label, "score": score} for value in context.synthetic_values
    ]
    with open(context.stub_spans_path, "w") as handle:
        json.dump(context.stub_spans, handle)


# --- When -----------------------------------------------------------------------------

@when('I commit the staged files with "{key}" set to "{value}" for that commit')
def step_commit_with_setting(context, key, value):
    context.head_before = world.head(context)
    context.result = world.git(
        context, "-c", "%s=%s" % (key, value), "commit", "-m", world.COMMIT_MESSAGE, check=False)
    context.was_commit = True


@step('I stage another harmless file "{name}"')
def step_stage_harmless(context, name):
    world.write_file(context, name, "Still nothing sensitive.\n")
    world.git(context, "add", name)


@step("I note the server process id")
def step_note_pid(context):
    result = world.leftblock(context, "deep-server", "status")
    found = SERVER_PID.search(result.stderr)
    assert result.returncode == 0 and found, "no server is running:\n" + result.stderr
    context.server_pid = found.group(1)


@when("{count:d} copies of the repository check their staged changes at the same time")
def step_concurrent_checks(context, count):
    """Copies, since two checks in one repository would fight over its index lock."""
    folders = []
    for number in range(count):
        folder = os.path.join(context.root, "copy-%d" % number)
        shutil.copytree(context.repo, folder, symlinks=True)
        folders.append(folder)
    processes = [
        subprocess.Popen(
            [sys.executable, "-m", "leftblock.cli", "check"], cwd=folder, env=context.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for folder in folders
    ]
    context.exit_codes = []
    context.check_errors = []
    for process in processes:
        _, errors = process.communicate(timeout=world.TIMEOUT)
        context.exit_codes.append(process.returncode)
        context.check_errors.append(errors)


@step("within {seconds:d} seconds no Privacy Filter server is running")
def step_server_exits(context, seconds):
    deadline = time.monotonic() + seconds
    while _server_running(context):
        assert time.monotonic() < deadline, "the server is still running"
        time.sleep(0.5)


# --- Then -------------------------------------------------------------------------------

@then("no Privacy Filter server is running")
def step_no_server(context):
    assert not _server_running(context), "a Privacy Filter server is running"


@then("the server process id is unchanged")
def step_pid_unchanged(context):
    result = world.leftblock(context, "deep-server", "status")
    found = SERVER_PID.search(result.stderr)
    assert found and found.group(1) == context.server_pid, (
        "server changed from %s:\n%s" % (context.server_pid, result.stderr))


@then("every check exits with {code:d}")
def step_every_exit(context, code):
    assert context.exit_codes == [code] * len(context.exit_codes), (
        context.exit_codes, context.check_errors)


@then("exactly one Privacy Filter server was started")
def step_one_server(context):
    logs = _server_files(context, "*.log")
    starts = sum(len(SERVER_START.findall(open(path).read())) for path in logs)
    assert starts == 1, "%d servers were started" % starts


@then("the server directory is accessible only by its owner")
def step_directory_private(context):
    mode = stat.S_IMODE(os.stat(_run_directory(context)).st_mode)
    assert mode == 0o700, oct(mode)


@then("the server socket is accessible only by its owner")
def step_socket_private(context):
    sockets = _server_files(context, "*.sock")
    assert len(sockets) == 1, sockets
    mode = stat.S_IMODE(os.stat(sockets[0]).st_mode)
    assert mode == 0o600, oct(mode)


@then("the server socket is gone")
def step_socket_gone(context):
    assert not _server_files(context, "*.sock"), _server_files(context, "*.sock")


@then("the server log records that the server started and was ready")
def step_log_lifecycle(context):
    text = "".join(open(path).read() for path in _server_files(context, "*.log"))
    assert "start pid" in text and "ready" in text, text


@then("the server log contains no staged text")
def step_log_has_no_text(context):
    text = "".join(open(path).read() for path in _server_files(context, "*.log"))
    assert text, "the server wrote no log"
    for value in context.synthetic_values + ["contacts.cfg", "phone"]:
        assert value not in text, "the log reveals staged content"


@then("the commit includes the allow file")
def step_commit_has_allow_file(context):
    names = world.git(context, "show", "--name-only", "--format=", "HEAD").stdout.split()
    assert ".leftblock-allow.yml" in names, names
