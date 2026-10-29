import os
import sys
import subprocess
import hmac
import hashlib
import json
import time
import shlex
from datetime import datetime
from typing import List, Dict, Any, Tuple
import tempfile
import yaml

SECRET_FILE_DEFAULT = os.environ.get("LEFTBLOCK_SECRET_PATH", os.path.expanduser("~/.config/leftblock/secret"))

def get_secret(secret_path: str = SECRET_FILE_DEFAULT) -> str:
    if not os.path.exists(secret_path):
        raise FileNotFoundError(f"Secret file not found at {secret_path}")
    with open(secret_path, 'r') as f:
        return f.read().strip()

def compute_hmac(tree_hash: str, validator: str, result: str, timestamp: str, secret: str) -> str:
    msg = f"{tree_hash}|{validator}|{result}|{timestamp}".encode('utf-8')
    return hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()

def run_cmd(cmd: List[str], check: bool = True, capture_output: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True, **kwargs)

class UnmergedIndexError(Exception):
    """The index holds unresolved merge conflicts, so it has no tree."""


UNMERGED_MESSAGE = (
    "The index has unresolved conflicts, so there is nothing to inspect yet. "
    "Resolve the conflicts and stage the result first."
)


def get_tree_hash() -> str:
    try:
        return run_cmd(["git", "write-tree"]).stdout.strip()
    except subprocess.CalledProcessError as error:
        if "unmerged" in (error.stderr or "").lower():
            raise UnmergedIndexError(UNMERGED_MESSAGE) from error
        raise

def get_commit_tree_hash(commit_sha: str) -> str:
    output = run_cmd(["git", "cat-file", "-p", commit_sha]).stdout
    for line in output.splitlines():
        if line.startswith("tree "):
            return line.split(" ")[1].strip()
    return ""

def load_config(repo_root: str, config_path: str = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = os.path.join(repo_root, ".leftblock.yml")
    if not os.path.exists(config_path):
        return {}
    with open(config_path, 'r') as f:
        return yaml.safe_load(f) or {}


def validate_checkers(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reject missing or unusable policy instead of signing an uninspected tree."""
    if not isinstance(config, dict):
        raise ValueError("Invalid checker configuration")
    checkers = config.get("checkers")
    if not isinstance(checkers, list) or not checkers:
        raise ValueError("No checkers configured")
    for checker in checkers:
        if not isinstance(checker, dict):
            raise ValueError("Invalid checker configuration")
        ctype = checker.get("type", "command")
        key = "command" if ctype == "command" else "procedure"
        if ctype not in ("command", "tactus") or not isinstance(checker.get(key), str) or not checker[key].strip():
            raise ValueError("Invalid checker configuration")
        if ctype == "command":
            success = checker.get("success_codes", [0])
            findings = checker.get("finding_codes", [1])
            for codes in (success, findings):
                if not isinstance(codes, list) or not codes or any(type(c) is not int for c in codes):
                    raise ValueError("Invalid checker exit-code policy")
            if set(success) & set(findings):
                raise ValueError("Checker success and finding codes must not overlap")
    return checkers

class CheckerResult:
    def __init__(self, name: str, clean: bool, findings: Any = None, error: bool = False):
        self.name = name
        self.clean = clean
        self.findings = findings
        self.error = error


def index_environment(env=None):
    """Resolve a caller-relative alternate index before changing checker cwd."""
    source = os.environ if env is None else env
    index = source.get("GIT_INDEX_FILE")
    if index and not os.path.isabs(index):
        return dict(source, GIT_INDEX_FILE=os.path.abspath(index))
    return env


def run_command_checker(checker: Dict[str, Any], cwd: str = None, env: Dict[str, str] = None) -> CheckerResult:
    name = checker.get('name', 'unknown')
    cmd = checker.get('command', '')
    success_codes = checker.get('success_codes', [0])
    finding_codes = checker.get('finding_codes', [1])
    report_file = None
    try:
        # Split before substitution so a TMPDIR with spaces stays one argument.
        argv = shlex.split(cmd)
        if "{report_file}" in cmd:
            fd, report_file = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            argv = [arg.replace("{report_file}", report_file) for arg in argv]
        proc = run_cmd(argv, check=False, capture_output=True, cwd=cwd, env=index_environment(env))
        if proc.returncode in success_codes:
            return CheckerResult(name, True)
        if proc.returncode not in finding_codes:
            return CheckerResult(name, False, "Checker failed; output suppressed.", error=True)
        findings = "Findings detected; checker output suppressed."
        if report_file:
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                if not isinstance(report, list) or not report or any(not isinstance(item, dict) for item in report):
                    raise ValueError("Invalid report")
                # Never carry matched values, source lines or raw logs into the UI.
                # Files, rule identifiers, the rule's own description (ruleset text,
                # not data), and line and column positions are the diagnostic
                # boundary. Gitleaks runs with --redact, so the matched value is
                # re-read from the staged line by position only to compute the
                # override id and to validate checksummed formats
                # (see leftblock.validators and leftblock.allow.attach_ids).
                findings = []
                for item in report:
                    finding = {key: item[key] for key in ("File", "RuleID") if isinstance(item.get(key), str)}
                    if isinstance(item.get("Description"), str) and item["Description"].strip():
                        finding["description"] = item["Description"]
                    for key in ("StartLine", "EndLine", "StartColumn", "EndColumn"):
                        if type(item.get(key)) is int:
                            finding[key] = item[key]
                    findings.append(finding)
            except (OSError, ValueError, TypeError):
                return CheckerResult(name, False, "Checker report unavailable or invalid; output suppressed.", error=True)
        return CheckerResult(name, False, findings)
    except (OSError, ValueError):
        return CheckerResult(name, False, "Checker could not run; check its installation and configuration.", error=True)
    finally:
        if report_file and os.path.exists(report_file):
            os.remove(report_file)


def run_tactus_checker(checker: Dict[str, Any], cwd: str = None) -> CheckerResult:
    name = checker.get('name', 'tactus-scan')
    procedure = checker.get('procedure')
    if not procedure:
        return CheckerResult(name, False, "No procedure specified for tactus checker", error=True)
    try:
        proc = run_cmd(
            ["tactus", "run", procedure], check=False, capture_output=True,
            cwd=cwd, env=index_environment(),
        )
    except OSError:
        return CheckerResult(name, False, "Tactus could not run; check its installation.", error=True)
    is_clean = proc.returncode == 0
    return CheckerResult(
        name, is_clean,
        "Tactus reported a failure; output suppressed." if not is_clean else None,
        error=proc.returncode not in (0, 1),
    )

def execute_checkers(checkers: List[Dict[str, Any]], cwd: str = None, env: Dict[str, str] = None) -> List[CheckerResult]:
    results = []
    for checker in checkers:
        ctype = checker.get('type', 'command')
        if ctype == 'command':
            results.append(run_command_checker(checker, cwd=cwd, env=env))
        elif ctype == 'tactus':
            results.append(run_tactus_checker(checker, cwd=cwd))
        else:
            results.append(CheckerResult(checker.get('name', 'unknown'), False, f"Unknown checker type: {ctype}"))
    return results

def get_trailer(commit_sha: str, key: str) -> str:
    return run_cmd(["git", "log", "-1", commit_sha, f"--format=%(trailers:key={key},valueonly)"]).stdout.strip()
