"""Test-only stand-in for the Privacy Filter model (LEFTBLOCK_DEEP_DETECTOR).

CI cannot download the model, so the specs name this factory instead
(``stub_detector:factory``). The stub "recognises" exactly the values the
steps registered in the JSON file named by LEFTBLOCK_STUB_SPANS, each with a
label and a score, wherever they occur in the text it is given. It appends a
line to LEFTBLOCK_STUB_LOG on every call, so a scenario can tell whether the
model was consulted at all. LEFTBLOCK_STUB_MISSING_EXTRA makes the factory
fail as a missing optional extra would. LEFTBLOCK_STUB_FAIL_AFTER=N makes the
(N+1)th call raise, as an interrupted deep scan would.
"""

import json
import os


def factory():
    if os.environ.get("LEFTBLOCK_STUB_MISSING_EXTRA"):
        raise ImportError("transformers")
    return detect


def detect(text):
    log = os.environ.get("LEFTBLOCK_STUB_LOG")
    limit = os.environ.get("LEFTBLOCK_STUB_FAIL_AFTER")
    if limit is not None and log:
        calls = len(open(log).read().split()) if os.path.exists(log) else 0
        if calls >= int(limit):
            raise KeyboardInterrupt("the stub was interrupted")
    if log:
        with open(log, "a") as handle:
            handle.write("call\n")
    path = os.environ.get("LEFTBLOCK_STUB_SPANS")
    known = json.load(open(path)) if path and os.path.exists(path) else []
    spans = []
    for entry in known:
        start = text.find(entry["value"])
        while start != -1:
            end = start + len(entry["value"])
            spans.append((start, end, entry["label"], entry["score"]))
            start = text.find(entry["value"], end)
    return spans
