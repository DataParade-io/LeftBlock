"""Versioned reports for tools that run LeftBlock as a subprocess."""

import json
import os
import re
import subprocess
import sys

from leftblock import deep, scan

MODEL_TIMEOUT_SECONDS = 180


def _model_pass(paths, records, kanbus_data):
    # These settings must be present before Transformers or HF Hub is imported.
    env = {**os.environ, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
    request = {"paths": paths, "records": records, "kanbusPattern": kanbus_data.pattern}
    try:
        child = subprocess.run(
            [sys.executable, "-m", "leftblock.scan_report"],
            input=json.dumps(request).encode("ascii"),
            capture_output=True, timeout=MODEL_TIMEOUT_SECONDS, env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        return [], {"status": "unavailable", "reason": "timeout", "message": "The model reached its time limit."}
    except OSError:
        child = None

    if child is not None and child.returncode == 0:
        try:
            findings = json.loads(child.stdout)
            if isinstance(findings, list):
                return findings, {"status": "completed", "findingCount": len(findings)}
        except (ValueError, RecursionError):
            pass
    if child is not None and child.returncode == 3:
        return [], {
            "status": "unavailable", "reason": "missing-dependencies",
            "message": "Install the optional model dependencies with " + deep.INSTALL_HINT + ".",
        }
    return [], {
        "status": "unavailable", "reason": "model-error",
        "message": "Check that the model works and that its files are in the local cache.",
    }


def run(paths, records, model_mode, kanbus_data):
    """Run rules once; keep their results if the isolated model process fails."""
    report = {
        "schemaVersion": 1,
        "findings": [],
        "privacyFilter": {"status": "disabled" if model_mode == "off" else "not-run"},
    }
    try:
        rules = (scan.scan_paths(paths, kanbus_data=kanbus_data) if records is None
                 else scan.scan_records(records))
    except scan.ScanError as exc:
        report["rules"] = {"status": "error", "message": str(exc)}
        return report
    except OSError:
        report["rules"] = {"status": "error", "message": "Could not read scan input."}
        return report
    report["rules"] = {"status": "completed", "findingCount": len(rules)}
    if model_mode == "auto" and (paths or records):
        findings, report["privacyFilter"] = _model_pass(paths, records, kanbus_data)
        rules.extend(findings)
    if records is not None:
        for finding in rules:
            finding["id"] = finding.pop("file")
    report["findings"] = rules
    return report


def _worker():
    """Read private inputs from stdin, and return only model findings."""
    request = json.load(sys.stdin)
    options = (deep.load_detector, deep.DEFAULT_LABELS, deep.DEFAULT_THRESHOLD)
    if request["records"] is None:
        findings = scan.scan_paths(request["paths"], *options, rules=False,
                                   kanbus_data=re.compile(request["kanbusPattern"]))
    else:
        findings = scan.scan_records(request["records"], *options, rules=False)
    print(json.dumps(findings))


if __name__ == "__main__":
    try:
        _worker()
    except deep.ExtraMissing:
        sys.exit(3)
    except Exception:
        # Third-party exceptions can include fragments of source text.
        sys.exit(2)
