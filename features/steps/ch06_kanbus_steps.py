"""Chapter 6 (Kanbus board data): synthetic board documents and a board.

The kinds below describe a document's *content*; the scenario chooses the path
it is staged under, which is what decides whether the board exception applies.
All identifiers are random version-4 UUIDs built at run time.
"""

import json
import os
import random

from behave import given, then

import world
from synthetic_data import generator, token, uuid4, HEX

ACTOR = "actor" + "_id"
HOME = "/" + "Users/"


def _doc(value, **dump):
    return json.dumps(value, indent=2, **dump) + "\n"


@generator("board document with session-style fields")
def _session_fields(rng):
    ids = [uuid4(rng) for _ in range(3)]
    doc = {"session_id": ids[0], "provider_session_id": ids[1], "resumed_session": ids[2]}
    return _doc(doc), ids


@generator("board document with a prefixed session value")
def _prefixed_session(rng):
    value = uuid4(rng)
    return _doc({"session_id": "PPY-" + value}), [value]


@generator("board document with UUIDs in prose")
def _prose_uuids(rng):
    bare, prefixed = uuid4(rng), uuid4(rng)
    doc = {"description": "session " + bare + " reproduced it",
           "text": "see PPY-" + prefixed + " and BOTSPY-" + bare}
    return _doc(doc), [bare, prefixed]


@generator("board document with a nested actor id")
def _nested_actor(rng):
    value = uuid4(rng)
    return _doc({"payload": {ACTOR: value}}), [value]


@generator("board document with a split actor id")
def _split_actor(rng):
    value = uuid4(rng)
    return '"%s"\n:\n"%s"\n' % (ACTOR, value), [value]


@generator("board document with a plain user name as actor id")
def _plain_actor(rng):
    value = "local" + "user"
    return _doc({ACTOR: value}), [value]


@generator("minified board event")
def _minified_event(rng):
    ids = [uuid4(rng) for _ in range(4)]
    doc = {"event_id": ids[0], ACTOR: ids[1], "session_id": ids[2],
           "payload": {"comment_id": ids[3], "text": "x " + ids[3]}}
    return json.dumps(doc) + "\n", ids


@generator("board document with a personal email")
def _board_email(rng):
    value = token(rng, 6, "abcdefghij") + "." + token(rng, 7, "abcdefghij") + "@" + token(rng, 9, "abcdefghij") + ".com"
    return _doc({"assignee": value}), [value]


@generator("board document with a home path")
def _board_home(rng):
    user = token(rng, 9, "abcdefghijklmnop")
    return _doc({"description": "see %s%s/work" % (HOME, user)}), [user]


@generator("board document with two home paths")
def _board_two_homes(rng):
    users = [token(rng, 9, "abcdefghijklmnop") for _ in range(2)]
    doc = {"description": "see %s%s/work" % (HOME, users[0]),
           "notes": "and %s%s/play" % (HOME, users[1])}
    return _doc(doc), users


@generator("board document with an OpenAI key")
def _board_key(rng):
    value = "sk" + "-proj-" + token(rng, 56, HEX)
    return _doc({"text": "key " + value}), [value]


@generator("board document with an OpenAI key as actor id")
def _board_actor_key(rng):
    value = "sk" + "-proj-" + token(rng, 56, HEX)
    return _doc({ACTOR: value}), [value]


@generator("board event with an AWS account id in a comment")
def _board_event_account(rng):
    value = "7" + token(rng, 11, "0123456789")
    doc = {"event_type": "comment_added",
           "payload": {"comment_text": "deployed to account %s last night" % value}}
    return _doc(doc), [value]


@generator("board issue with an AWS resource id in its description")
def _board_issue_resource(rng):
    value = "d" + token(rng, 13, "abcdefghijklmnopqrstuvwxyz0123456789")
    doc = {"id": "PPY-x", "description": "preview at https://main.%s.amplifyapp.com" % value}
    return _doc(doc), [value]


@generator("board event with a personal email in a comment")
def _board_event_email(rng):
    value = token(rng, 6, "abcdefghij") + "." + token(rng, 7, "abcdefghij") + "@" + token(rng, 9, "abcdefghij") + ".com"
    doc = {"event_type": "comment_added", "payload": {"comment_text": "ask %s about it" % value}}
    return _doc(doc), [value]


# --- .kanbus.yml ------------------------------------------------------------

def _non_v4(rng):
    return "-".join([token(rng, 8, HEX), token(rng, 4, HEX), "1" + token(rng, 3, HEX),
                     "a" + token(rng, 3, HEX), token(rng, 12, HEX)])


@generator("Kanbus project id line")
def _project_id(rng):
    value = uuid4(rng)
    return "project_key: kbs\nproject_id: %s\n" % value, [value]


@generator("indented Kanbus project id")
def _indented_project_id(rng):
    value = uuid4(rng)
    return "realtime:\n  project_id: %s\n" % value, [value]


@generator("Kanbus session id line")
def _yml_session(rng):
    value = uuid4(rng)
    return "session_id: %s\n" % value, [value]


@generator("Kanbus project id with a version 1 UUID")
def _v1_project_id(rng):
    value = _non_v4(rng)
    return "project_id: %s\n" % value, [value]


# --- Realistic board ---------------------------------------------------------

@given("a staged Kanbus board with an issue, an event and a project id")
def step_board(context):
    _stage_board(context, "")


@given("a staged Kanbus board whose issue description mentions a synthetic home path")
def step_board_with_home_path(context):
    user = token(random.Random("board-home"), 9, "abcdefghijklmnop")
    context.synthetic_values.append(user)
    _stage_board(context, "See %s%s/notes for details" % (HOME, user))


def _stage_board(context, description):
    rng = random.Random("kanbus board")
    issue_id = "kanbus-" + uuid4(rng)
    context.kanbus_issue_file = "project/issues/%s.json" % issue_id
    stamp = "2026-10-20T10:00:00"
    issue = {
        "id": issue_id, "title": "Synthetic board item", "description": description,
        "type": "task", "status": "open", "priority": 2, "assignee": None,
        "parent": "kanbus-" + uuid4(rng), "labels": [], "dependencies": [],
        "comments": [{"id": uuid4(rng), "author": "agent", "text": "note",
                      "created_at": stamp + "Z"}],
        "created_at": stamp + "Z", "updated_at": stamp + "Z",
    }
    event_id = uuid4(rng)
    event = {
        "schema_version": 1, "event_id": event_id, "issue_id": issue_id,
        "event_type": "issue_created", "occurred_at": stamp + ".000Z",
        ACTOR: "agent", "payload": {"title": "Synthetic board item"},
    }
    files = {
        ".kanbus.yml": "project_key: kanbus\nproject_id: %s\n" % uuid4(rng),
        context.kanbus_issue_file: _doc(issue),
        "project/events/2026-10-20T10-00-00.000Z__%s.json" % event_id: _doc(event),
    }
    for name, content in files.items():
        world.write_file(context, name, content)
        world.git(context, "add", name)


@given("a staged Kanbus event and cache index saved with Windows line endings")
def step_board_with_windows_endings(context):
    """Canonical event JSON and cache index content, every line ending CRLF."""
    rng = random.Random("kanbus crlf")
    issue_id = "kanbus-" + uuid4(rng)
    event = {"event_id": uuid4(rng), ACTOR: uuid4(rng), "issue_id": issue_id}
    cache = {
        "file_mtimes": {issue_id + ".json": 1792500000.25},
        "issues": [{"id": issue_id, "description": "s " + uuid4(rng),
                    "session_id": uuid4(rng)}],
    }
    files = {
        "project/events/crlf-event.json": _doc(event),
        "project/.cache/index.json": _doc(cache),
    }
    for name, content in files.items():
        path = os.path.join(context.repo, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content.replace("\n", "\r\n").encode())
        assert b"\r\n" in open(path, "rb").read()
        world.git(context, "add", name)


@then("stderr names the staged Kanbus issue file")
def step_names_issue_file(context):
    assert context.kanbus_issue_file + ":" in context.result.stderr, context.result.stderr
