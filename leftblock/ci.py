import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from leftblock.core import compute_hmac, get_secret, load_config, run_cmd

DEFAULT_STATUS_CONTEXT = "leftblock/ci"
SIGNATURE_PREFIX = "hmac-sha256:"
SIGNATURE_DESCRIPTION_LENGTH = 12
EXIT_REFUSED = 2

TOOL_VERSION_COMMANDS = {
    "node": ["node", "-v"],
    "python3": ["python3", "--version"],
    "git": ["git", "--version"],
}


class CiRefusal(Exception):
    """The run was refused before any command ran, so no receipt exists."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def leftblock_package_version() -> str:
    try:
        from importlib.metadata import version
        return version("leftblock")
    except Exception:
        return "unknown"


def read_tool_version(argv: List[str], cwd: str) -> Optional[str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=cwd, check=False)
    except OSError:
        return None
    text = (proc.stdout or proc.stderr).strip()
    return text if proc.returncode == 0 and text else None


def collect_tool_versions(repo_root: str) -> Dict[str, Optional[str]]:
    versions = {name: read_tool_version(argv, repo_root) for name, argv in TOOL_VERSION_COMMANDS.items()}
    versions["leftblock"] = leftblock_package_version()
    return versions


def read_ci_settings(repo_root: str) -> Dict[str, Any]:
    ci_section = load_config(repo_root).get("ci")
    if not isinstance(ci_section, dict):
        raise CiRefusal("No ci section in .leftblock.yml; add ci.command to say what CI means for this repository.")
    command = ci_section.get("command")
    if not isinstance(command, str) or not command.strip():
        raise CiRefusal("ci.command in .leftblock.yml must be one non-empty shell command.")
    context = ci_section.get("status_context", DEFAULT_STATUS_CONTEXT)
    if not isinstance(context, str) or not context.strip():
        raise CiRefusal("ci.status_context in .leftblock.yml must be a non-empty string.")
    sign = ci_section.get("sign", False)
    if not isinstance(sign, bool):
        raise CiRefusal("ci.sign in .leftblock.yml must be true or false.")
    return {"command": command, "status_context": context, "sign": sign}


def resolve_exact_head(repo_root: str, requested_sha: str) -> Dict[str, str]:
    dirty = run_cmd(["git", "status", "--porcelain"], check=False, cwd=repo_root).stdout.strip()
    if dirty:
        raise CiRefusal("The work tree is not clean. Commit or stash your changes: a receipt is for exactly what was tested.")
    head = run_cmd(["git", "rev-parse", "HEAD"], check=False, cwd=repo_root)
    requested = run_cmd(["git", "rev-parse", "--verify", "-q", requested_sha + "^{commit}"], check=False, cwd=repo_root)
    if head.returncode != 0 or requested.returncode != 0:
        raise CiRefusal("Cannot resolve %s to a commit." % requested_sha)
    if requested.stdout.strip() != head.stdout.strip():
        raise CiRefusal("%s is not HEAD. Check it out first: a receipt is for exactly what was tested." % requested_sha)
    sha = head.stdout.strip()
    tree = run_cmd(["git", "rev-parse", sha + "^{tree}"], cwd=repo_root).stdout.strip()
    describe = run_cmd(["git", "describe", "--always"], check=False, cwd=repo_root).stdout.strip()
    return {"sha": sha, "tree": tree, "describe": describe}


def receipts_directory(repo_root: str) -> str:
    common = run_cmd(["git", "rev-parse", "--git-common-dir"], cwd=repo_root).stdout.strip()
    if not os.path.isabs(common):
        common = os.path.join(repo_root, common)
    return os.path.join(common, "leftblock", "receipts")


def build_receipt(identity: Dict[str, str], command: str, exit_code: int, duration_seconds: float,
                  started_at: str, finished_at: str, tools: Dict[str, Optional[str]],
                  secret: Optional[str]) -> Dict[str, Any]:
    result = "success" if exit_code == 0 else "failure"
    receipt = {
        "sha": identity["sha"],
        "tree": identity["tree"],
        "describe": identity["describe"],
        "checks": [{"command": command, "exit_code": exit_code, "duration_s": round(duration_seconds, 3)}],
        "result": result,
        "started_at": started_at,
        "finished_at": finished_at,
        "tools": tools,
        "leftblock_version": tools.get("leftblock", "unknown"),
        "host": socket.gethostname(),
    }
    if secret is not None:
        receipt["signature"] = SIGNATURE_PREFIX + compute_hmac(
            identity["sha"], identity["tree"], result, finished_at, secret,
        )
    return receipt


def write_receipt(repo_root: str, receipt: Dict[str, Any]) -> str:
    directory = receipts_directory(repo_root)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, receipt["sha"] + ".json")
    with open(path, "w") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def describe_status(receipt: Dict[str, Any]) -> str:
    checks = receipt["checks"]
    duration = sum(check["duration_s"] for check in checks)
    text = "%s %d checks %ds" % (receipt["result"], len(checks), round(duration))
    signature = receipt.get("signature")
    if signature:
        text += " sig:" + signature[len(SIGNATURE_PREFIX):][:SIGNATURE_DESCRIPTION_LENGTH]
    return text


def post_commit_status(repo_root: str, receipt: Dict[str, Any], status_context: str) -> None:
    argv = [
        "gh", "api", "repos/{owner}/{repo}/statuses/" + receipt["sha"],
        "-f", "state=" + receipt["result"],
        "-f", "context=" + status_context,
        "-f", "description=" + describe_status(receipt),
        "-f", "target_url=",
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=repo_root, check=False)
    except OSError:
        raise RuntimeError("The gh command could not run; install GitHub CLI or pass --no-status.")
    if proc.returncode != 0:
        raise RuntimeError("Posting the commit status failed: %s" % (proc.stderr.strip() or "gh exited %d" % proc.returncode))


def run_ci(repo_root: str, requested_sha: str, post_status: bool, dry_run: bool) -> int:
    settings = read_ci_settings(repo_root)
    identity = resolve_exact_head(repo_root, requested_sha)
    secret = None
    if settings["sign"]:
        try:
            secret = get_secret()
        except FileNotFoundError as error:
            raise CiRefusal("ci.sign is true but %s" % error)

    if dry_run:
        print("leftblock ci (dry run): would run `%s` on %s (tree %s)" % (settings["command"], identity["sha"], identity["tree"]))
        print("  receipt: %s" % os.path.join(receipts_directory(repo_root), identity["sha"] + ".json"))
        print("  status: %s" % ("would post %s" % settings["status_context"] if post_status else "not posted"))
        print("  signed: %s" % ("yes" if secret is not None else "no"))
        return 0

    tools = collect_tool_versions(repo_root)
    started_at = utc_timestamp()
    started_clock = time.monotonic()
    completed = subprocess.run(settings["command"], shell=True, cwd=repo_root)
    duration_seconds = time.monotonic() - started_clock
    finished_at = utc_timestamp()
    exit_code = completed.returncode if completed.returncode > 0 else (0 if completed.returncode == 0 else 1)

    receipt = build_receipt(identity, settings["command"], exit_code, duration_seconds,
                            started_at, finished_at, tools, secret)
    path = write_receipt(repo_root, receipt)
    print("leftblock ci: %s on %s; receipt %s" % (receipt["result"], identity["sha"], path))

    if post_status:
        try:
            post_commit_status(repo_root, receipt, settings["status_context"])
        except RuntimeError as error:
            print("leftblock ci: %s" % error, file=sys.stderr)
            return exit_code if exit_code != 0 else 1
        print("leftblock ci: posted %s as %s" % (settings["status_context"], receipt["result"]))
    return exit_code

