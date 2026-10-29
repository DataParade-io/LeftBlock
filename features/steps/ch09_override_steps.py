"""Steps for chapter 9: recorded overrides and their whole lifecycle.

Chapter-specific; the shared vocabulary lives in common_steps.py.
"""

import json
import os
import re

import yaml
from behave import given, step, then, when

import world
from synthetic_data import LOWER, token

ALLOW_FILE = ".leftblock-allow.yml"
FINDING_ID = re.compile(r"^      .*\[id ([0-9a-f]{16})\](?: \(.*\))?$", re.MULTILINE)


def _staged_allow_text(context):
    return world.git(context, "show", ":" + ALLOW_FILE).stdout


def _staged_entries(context):
    return yaml.safe_load(_staged_allow_text(context))["allow"]


def _allow(context, ids, *extra):
    context.head_before = world.head(context)
    context.result = world.leftblock(context, "allow", *ids, *extra)
    context.was_commit = False


def _new_address(context):
    value = token(context.address_rng, 6, LOWER) + "." + token(context.address_rng, 7, LOWER)
    value += "@" + token(context.address_rng, 9, LOWER) + ".com"
    context.synthetic_values.append(value)
    return value


def _rng(context):
    import random
    if not hasattr(context, "address_rng"):
        context.address_rng = random.Random("override addresses")


# --- Noting findings ----------------------------------------------------

@when("I note the finding ids from a dry run")
def step_note_ids(context):
    """Run ``leftblock check``; it must block, and its finding ids are remembered."""
    context.result = world.leftblock(context, "check")
    assert context.result.returncode == 1, context.result.stderr
    context.noted_ids = FINDING_ID.findall(context.result.stderr)
    assert context.noted_ids, "no finding ids shown:\n" + context.result.stderr


# --- Recording overrides ------------------------------------------------

@step('I record an override for the noted findings because "{reason}"')
def step_record(context, reason):
    """``leftblock allow <ids> --reason <reason>`` for every noted id."""
    _allow(context, context.noted_ids, "--reason", reason)


@step("I record an override for the noted findings without giving a reason")
def step_record_no_reason(context):
    """``leftblock allow <ids>`` with no --reason option at all."""
    _allow(context, context.noted_ids)


@step("I record an override for the noted findings twice")
def step_record_twice(context):
    """The same ``allow`` command twice; both must succeed."""
    for _ in range(2):
        _allow(context, context.noted_ids, "--reason", "Public role address for the site")
        assert context.result.returncode == 0, context.result.stderr


@step("I record an override for the noted findings quoting the flagged address in the reason")
def step_record_quoting(context):
    """A reason that repeats the most recently generated flagged value."""
    reason = "Public address %s on the site" % context.synthetic_values[-1]
    _allow(context, context.noted_ids, "--reason", reason)


@step("I try to record an override for an id that no finding has")
def step_record_unknown(context):
    """``leftblock allow`` with a well-formed id that matches nothing."""
    unknown = "0123456789abcdef"
    assert unknown not in getattr(context, "noted_ids", [])
    _allow(context, [unknown], "--reason", "Reviewed and not sensitive")


# --- Changing staged content -------------------------------------------

@step('I add a second personal address to "{name}" and stage it')
def step_add_second(context, name):
    """Append a line holding a different personal address, then stage the file."""
    _rng(context)
    world.write_file(context, name, "also: %s\n" % _new_address(context), append=True)
    world.git(context, "add", name)


@step('I reword the flagged line of "{name}" and stage it')
def step_reword_line(context, name):
    """Change the text around the flagged value (so the line's content differs)."""
    path = os.path.join(context.repo, name)
    with open(path) as handle:
        text = handle.read()
    assert "contact:" in text
    with open(path, "w") as handle:
        handle.write(text.replace("contact:", "write to:"))
    world.git(context, "add", name)


@step('I extend "{name}" with a personal address and stage it')
def step_extend_with_address(context, name):
    """Append a line holding a personal address to an existing file and stage it."""
    _rng(context)
    world.write_file(context, name, "contact: %s\n" % _new_address(context), append=True)
    world.git(context, "add", name)


@given('a committed file "{name}" of three plain lines')
def step_three_lines(context, name):
    """Commit (without the hook) a file of three harmless lines."""
    world.write_file(context, name, "one\ntwo\nthree\n")
    world.git(context, "add", name)
    world.git(context, "commit", "-q", "--no-verify", "-m", "chore: add " + name)


@step("I unstage the allow file")
def step_unstage_allow(context):
    """Remove the allow file from the index but keep it in the working tree."""
    world.git(context, "reset", "-q", "--", ALLOW_FILE)


@step("the staged allow file has its reason reworded to quote the flagged address")
def step_reason_quotes_value(context):
    """Hand-edit the reason in the allow file to contain the flagged address."""
    path = os.path.join(context.repo, ALLOW_FILE)
    data = yaml.safe_load(open(path).read())
    data["allow"][0]["reason"] = "Address %s is public" % context.synthetic_values[-1]
    with open(path, "w") as handle:
        handle.write(yaml.safe_dump(data))
    world.git(context, "add", ALLOW_FILE)


@step("the staged allow file has its reason emptied by hand")
def step_reason_emptied(context):
    """Hand-edit the first entry to have an empty reason and stage the file."""
    path = os.path.join(context.repo, ALLOW_FILE)
    data = yaml.safe_load(open(path).read())
    data["allow"][0]["reason"] = ""
    with open(path, "w") as handle:
        handle.write(yaml.safe_dump(data))
    world.git(context, "add", ALLOW_FILE)


@step("the allow file has its category line removed by hand and is staged")
def step_kind_removed(context):
    """Delete the informational ``kind:`` line and stage the file."""
    path = os.path.join(context.repo, ALLOW_FILE)
    lines = open(path).read().splitlines()
    kept = [line for line in lines if not line.strip().startswith("kind:")]
    assert len(kept) < len(lines), "no kind line was present"
    with open(path, "w") as handle:
        handle.write("\n".join(kept) + "\n")
    world.git(context, "add", ALLOW_FILE)


@step("the allow file gets a local note that is not staged")
def step_local_note(context):
    """Append a comment to the working-tree allow file only."""
    world.write_file(context, ALLOW_FILE, "# local note\n", append=True)


@given("the configured scanner is not installed")
def step_missing_scanner(context):
    """A root policy whose only scanner is a program that does not exist."""
    policy = {"version": 1, "checkers": [
        {"name": "absent-scanner", "type": "command",
         "command": "definitely-missing-scanner-binary --scan"},
    ]}
    world.write_file(context, ".leftblock.yml", json.dumps(policy))


# --- Remembering the allow file ---------------------------------------

@step("I remember the allow file and what is staged for it")
def step_remember_allow(context):
    """Snapshot the working-tree allow file and its index entry."""
    path = os.path.join(context.repo, ALLOW_FILE)
    context.remembered_allow = open(path, "rb").read() if os.path.exists(path) else None
    context.remembered_index = world.git(context, "ls-files", "--stage", "--", ALLOW_FILE).stdout


@then("the allow file and what is staged for it are as remembered")
def step_allow_as_remembered(context):
    """The working-tree allow file and its index entry match the snapshot."""
    path = os.path.join(context.repo, ALLOW_FILE)
    now = open(path, "rb").read() if os.path.exists(path) else None
    assert now == context.remembered_allow, "the allow file changed"
    index = world.git(context, "ls-files", "--stage", "--", ALLOW_FILE).stdout
    assert index == context.remembered_index, "the staged allow file changed"


# --- Assertions -------------------------------------------------------

@then("the allow file is staged and nothing was committed")
def step_allow_staged(context):
    """The allow file is in the index and HEAD is where it was."""
    assert world.git(context, "ls-files", "--stage", "--", ALLOW_FILE).stdout.strip()
    assert world.head(context) == context.head_before, "HEAD moved"


@then("there is no allow file in the working tree or the index")
def step_no_allow(context):
    """Nothing was recorded: no file on disk and no index entry."""
    assert not os.path.exists(os.path.join(context.repo, ALLOW_FILE))
    assert world.git(context, "ls-files", "--stage", "--", ALLOW_FILE).stdout == ""


@then('the staged allow file has an entry for rule "{rule}" in "{file}" with the reason "{reason}"')
def step_entry(context, rule, file, reason):
    """The first staged entry has the given rule, file and reason, a 16-hex id and a date."""
    entry = _staged_entries(context)[0]
    assert (entry["rule"], entry["file"], entry["reason"]) == (rule, file, reason), entry
    assert re.fullmatch(r"[0-9a-f]{16}", entry["id"]), entry
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(entry["added"])), entry


@then('the staged allow file entry records the category "{kind}"')
def step_entry_kind(context, kind):
    """The first staged entry's ``kind`` is ``kind``."""
    assert _staged_entries(context)[0]["kind"] == kind


@then("the staged allow file does not contain any flagged value")
def step_allow_has_no_value(context):
    """No generated value appears in the staged allow file."""
    text = _staged_allow_text(context)
    for value in context.synthetic_values:
        assert value not in text


@then("the staged allow file records {count:d} override")
@then("the staged allow file records {count:d} overrides")
def step_entry_count(context, count):
    """The staged allow file holds exactly ``count`` entries."""
    assert len(_staged_entries(context)) == count


@then("the working allow file is not staged")
def step_allow_unstaged(context):
    """The allow file exists on disk but has no index entry."""
    assert os.path.exists(os.path.join(context.repo, ALLOW_FILE))
    assert world.git(context, "ls-files", "--stage", "--", ALLOW_FILE).stdout == ""


@then("every noted finding id appears in the output")
def step_ids_in_output(context):
    """Each noted id is shown by the last command."""
    for ident in context.noted_ids:
        assert ident in world.output(context), ident


@then("the noted finding ids no longer appear in the findings")
def step_ids_gone(context):
    """None of the noted ids are listed by the last (blocked) dry run."""
    shown = FINDING_ID.findall(context.result.stderr)
    assert not set(shown) & set(context.noted_ids), shown


@then("exactly {count:d} finding is listed")
@then("exactly {count:d} findings are listed")
def step_finding_count(context, count):
    """The last blocked dry run listed ``count`` findings with ids."""
    assert len(FINDING_ID.findall(context.result.stderr)) == count, context.result.stderr


@then("no finding is listed with an id")
def step_no_ids(context):
    """The last dry run shows no finding id (nothing can be overridden)."""
    assert FINDING_ID.findall(context.result.stderr) == [], context.result.stderr


@then("the final line of the output names the finding and its next step")
def step_last_line(context):
    """The last stderr line alone says what is blocked and how to proceed."""
    last = context.result.stderr.strip().splitlines()[-1]
    ident = context.noted_ids[0]
    assert "Inspection blocked" in last, last
    assert "leftblock-personal-email in page.tsx:1 [id %s]" % ident in last, last
    assert "Remove the flagged content" in last, last
    assert "allow " + ident in last, last
    assert "\033[" not in last, last


@step('I stage a copy of the flagged line in "{name}"')
def step_copy_flagged_line(context, name):
    """Write the exact flagged line of page.tsx into a second file and stage it."""
    with open(os.path.join(context.repo, "page.tsx")) as handle:
        line = handle.read()
    world.write_file(context, name, line)
    world.git(context, "add", name)


# --- Match-based ids and the older line-based ones ------------------------

def _flagged_value(context):
    return context.synthetic_values[-1]


def _staged_line_with(context, name, value):
    text = world.git(context, "show", ":" + name).stdout
    lines = [line for line in text.split("\n") if value in line]
    assert lines, "no staged line of %s holds the flagged value" % name
    return lines[0]


def _sha_id(rule, name, content):
    import hashlib
    return hashlib.sha256(("%s\0%s\0%s" % (rule, name, content)).encode()).hexdigest()[:16]


@step('I replace the staged allow file with a line-based entry for rule "{rule}" on the flagged line of "{name}"')
def step_legacy_entry(context, rule, name):
    """What earlier versions recorded: an id hashing the rule, file and whole line."""
    ident = _sha_id(rule, name, _staged_line_with(context, name, _flagged_value(context)))
    text = (
        "version: 1\nallow:\n"
        '  - id: "%s"\n    rule: "%s"\n    file: "%s"\n'
        '    reason: "Recorded by an earlier version of LeftBlock"\n' % (ident, rule, name)
    )
    world.write_file(context, ALLOW_FILE, text)
    world.git(context, "add", ALLOW_FILE)
    context.legacy_id = ident


@step('I add the flagged address to "{name}" again on another line and stage it')
def step_repeat_value(context, name):
    """Append a second line holding the same personal address, then stage the file."""
    world.write_file(context, name, "again: %s\n" % _flagged_value(context), append=True)
    world.git(context, "add", name)


@step('I replace the flagged address in "{name}" with another personal address and stage it')
def step_replace_value(context, name):
    """Swap the matched address for a different one, leaving the rest of the line."""
    _rng(context)
    old = _flagged_value(context)
    path = os.path.join(context.repo, name)
    with open(path) as handle:
        text = handle.read()
    with open(path, "w") as handle:
        handle.write(text.replace(old, _new_address(context)))
    world.git(context, "add", name)


@step('I add text around the flagged address in "{name}" and stage it')
def step_add_text_around(context, name):
    """Change the rest of the line (before and after the value) and stage the file."""
    value = _flagged_value(context)
    path = os.path.join(context.repo, name)
    with open(path) as handle:
        text = handle.read()
    with open(path, "w") as handle:
        handle.write(text.replace(value, "<a href=\"x\">" + value + "</a> (updated copy)"))
    world.git(context, "add", name)


@then('the staged allow file entry for "{name}" has the id of its rule and the flagged value alone')
def step_entry_match_id(context, name):
    """The recorded id hashes rule, file and the matched value, not the whole line."""
    entry = _staged_entries(context)[0]
    expected = _sha_id(entry["rule"], name, _flagged_value(context))
    assert entry["id"] == expected, (entry["id"], expected)
    line = _staged_line_with(context, name, _flagged_value(context))
    assert entry["id"] != _sha_id(entry["rule"], name, line)


@then("every override that applied is reported under its recorded id")
def step_reported_recorded_id(context):
    assert 'id %s' % context.legacy_id in context.result.stderr, context.result.stderr
