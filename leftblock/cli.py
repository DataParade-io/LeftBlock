import argparse
import sys
import os
import re
import json
import subprocess
import getpass
import hashlib
import shlex
import shutil
import signal
import yaml
from datetime import datetime, timezone
from leftblock.merge import (
    MergeScopeError, build_scoped_index, checker_environment, index_entries, merge_state,
)
from leftblock import allow as allowlist
from leftblock import bypass
from leftblock import deep
from leftblock import scan
from leftblock import validators
from leftblock.core import (
    get_secret, compute_hmac, get_tree_hash, get_commit_tree_hash,
    load_config, validate_checkers, execute_checkers, get_trailer, run_cmd, SECRET_FILE_DEFAULT,
    CheckerResult, UnmergedIndexError, UNMERGED_MESSAGE,
)

def _label(text, color):
    # Plain labels when output is captured (git GUIs, wrappers, CI) or NO_COLOR is set.
    if os.environ.get("NO_COLOR") or not sys.stderr.isatty():
        return text
    return f"\033[{color}m{text}\033[0m"

def print_info(msg):
    print(f"{_label('[leftblock]', '1;34')} {msg}", file=sys.stderr)

def print_warn(msg):
    print(f"{_label('[leftblock]', '1;33')} {msg}", file=sys.stderr)

def print_err(msg):
    print(f"{_label('[leftblock ERROR]', '1;31')} {msg}", file=sys.stderr)

DEFAULT_LEFTBLOCK_YML = """\
version: 1
checkers:
  - name: gitleaks
    type: command
    command: gitleaks protect --staged --ignore-gitleaks-allow --config .leftblock/gitleaks.toml --redact --no-banner --report-format json --report-path {report_file}
    success_codes: [0]
    finding_codes: [1]
"""

def write_default_configs(repo_root):
    """Install the zero-config defaults into a repo.

    Writes a default .leftblock.yml (pointing at the shipped gitleaks
    ruleset) and copies the packaged gitleaks.toml into
    <repo>/.leftblock/. Existing files are never overwritten.
    """
    config_dir = os.path.join(repo_root, ".leftblock")
    leftblock_yml = os.path.join(repo_root, ".leftblock.yml")
    ruleset_target = os.path.join(config_dir, "gitleaks.toml")

    if not os.path.exists(leftblock_yml):
        with open(leftblock_yml, "w") as f:
            f.write(DEFAULT_LEFTBLOCK_YML)
        print_info(f"Wrote default checker config at {leftblock_yml}")
    else:
        print_info(f"Existing {leftblock_yml} left untouched.")

    packaged_ruleset = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "gitleaks.toml"
    )
    if os.path.exists(packaged_ruleset):
        os.makedirs(config_dir, exist_ok=True)
        if not os.path.exists(ruleset_target):
            import shutil
            shutil.copyfile(packaged_ruleset, ruleset_target)
            print_info(f"Installed shipped gitleaks ruleset at {ruleset_target}")
        else:
            print_info(f"Existing {ruleset_target} left untouched.")
    else:
        print_warn(f"Packaged ruleset missing at {packaged_ruleset}; default gitleaks rules only.")

def cmd_install(args):
    """Setup the git hook and secret."""
    repo_root = run_cmd(
        ["git", "rev-parse", "--show-toplevel"], check=False
    ).stdout.strip()
    if not repo_root:
        print_err("Run installation inside a Git repository.")
        sys.exit(1)
    if getattr(args, "local", False) or getattr(args, "check_only", False):
        if not (args.local and args.check_only):
            print_err("Use --local and --check-only together for a local pre-commit gate.")
            sys.exit(1)
        from leftblock.hooks import install_local_check_hook
        try:
            notes = install_local_check_hook(repo_root, getattr(args, "gitleaks", None))
        except (ValueError, OSError) as exc:
            print_err(str(exc))
            sys.exit(1)
        for level, note in notes or []:
            (print_warn if level == "warn" else print_info)(note)
        print_info("Installed local LeftBlock pre-commit gate; no signing secret is needed.")
        return
    if getattr(args, "gitleaks", None):
        print_err("--gitleaks is supported with --local --check-only.")
        sys.exit(1)
    from leftblock.hooks import install_hook
    try:
        install_hook(repo_root)
    except (ValueError, OSError) as exc:
        print_err(str(exc))
        sys.exit(1)
    write_default_configs(repo_root)
    print_info("Installed LeftBlock commit-msg hook.")

    # Generate secret if needed
    secret_dir = os.path.dirname(SECRET_FILE_DEFAULT)
    if not os.path.exists(SECRET_FILE_DEFAULT):
        os.makedirs(secret_dir, exist_ok=True)
        secret = os.urandom(16).hex()
        with open(SECRET_FILE_DEFAULT, 'w') as f:
            f.write(secret)
        os.chmod(SECRET_FILE_DEFAULT, 0o600)
        print_info(f"Generated new shared secret at {SECRET_FILE_DEFAULT}")
    else:
        print_info(f"Shared secret already exists at {SECRET_FILE_DEFAULT}")

CONFIG_ERROR = "Missing or invalid checker configuration. Inspection blocked; review the selected policy."

# Exit codes of `check`.
EXIT_PASSED, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2


class ConfigError(Exception):
    pass


def run_checks(repo_root, config_path=None, overrides=True):
    """Run the checkers, attach override ids and apply staged overrides.

    Returns (config, results, applied) where applied is [(finding, reason)] for
    each override that took effect. Prints nothing.
    """
    config, results = _run_configured_checks(repo_root, config_path)
    validators.check_findings(repo_root, results)
    allowlist.attach_ids(repo_root, results)
    applied = []
    if not overrides:
        return config, results, applied
    try:
        entries = allowlist.load_allowlist(repo_root)
    except allowlist.AllowError:
        results.append(CheckerResult(
            "leftblock-allow", False,
            "Invalid .leftblock-allow.yml; inspection blocked.", error=True,
        ))
        return config, results, applied
    shown = set()
    for finding, reason in allowlist.apply_allowlist(results, entries):
        # Several matches on one line share an id; report each override once.
        if finding["id"] in shown:
            continue
        shown.add(finding["id"])
        applied.append((finding, reason))
    return config, results, applied


def print_applied(applied):
    for finding, reason in applied:
        print_info(
            "Override applied: file " + json.dumps(finding["File"], ensure_ascii=True)
            + ", rule " + json.dumps(finding["RuleID"], ensure_ascii=True)
            + ", id " + finding["id"]
            + ", reason " + json.dumps(reason, ensure_ascii=True)
        )


def warn_root_gitleaksignore(repo_root):
    """Gitleaks always honours a root .gitleaksignore; say so on every run."""
    if os.path.isfile(os.path.join(repo_root, ".gitleaksignore")):
        print_warn(
            "This repository has a root .gitleaksignore. Gitleaks skips its entries "
            "with no recorded reason; prefer leftblock allow for new exceptions."
        )


def configured_checks(repo_root, config_path=None, overrides=True):
    """run_checks, announcing each applied override on stderr."""
    try:
        config, results, applied = run_checks(repo_root, config_path, overrides)
    except ConfigError:
        print_err(CONFIG_ERROR)
        sys.exit(1)
    print_applied(applied)
    return config, results


def _run_configured_checks(repo_root, config_path=None):
    try:
        config = load_config(repo_root, config_path)
        checkers = validate_checkers(config)
    except (OSError, ValueError, yaml.YAMLError):
        raise ConfigError(CONFIG_ERROR)
    # Inherited whole files at the same path can be omitted during a merge.
    # Changed/resolved files and renamed paths keep their full staged diff.
    # Any failure to scope falls back to the full staged scan (stricter).
    scoped_index = None
    try:
        base_env = checker_environment()
    except (MergeScopeError, ValueError):
        return config, [CheckerResult(
            "git-environment", False, "Invalid Git checker environment.", error=True,
        )]
    try:
        state = merge_state(repo_root)
        if state:
            scoped_index = build_scoped_index(repo_root, state[1], head=state[0])
            entries = index_entries(repo_root, scoped_index)
            env = checker_environment(scoped_index)
    except (MergeScopeError, OSError, ValueError):
        if scoped_index and os.path.exists(scoped_index):
            os.remove(scoped_index)
        scoped_index = None
    try:
        results = execute_checkers(checkers, cwd=repo_root, env=env if scoped_index else base_env)
        # Gitleaks skips lines with its inline allow comment and .gitleaksignore entries with no
        # recorded reason; report staged additions of either as findings.
        try:
            skips = bypass.bypass_findings(repo_root, env if scoped_index else base_env)
            if skips:
                results.append(CheckerResult("leftblock-bypass", False, skips))
        except bypass.BypassScanError:
            results.append(CheckerResult(
                "leftblock-bypass", False, "Could not read the staged diff.", error=True,
            ))
        if scoped_index:
            try:
                stable = merge_state(repo_root) == state and index_entries(repo_root, scoped_index) == entries
            except (MergeScopeError, OSError, ValueError):
                stable = False
            if not stable:
                results.append(CheckerResult(
                    "merge-scope", False,
                    "Merge state or inspected index changed during inspection. Retry the check.",
                    error=True,
                ))
        return config, results
    finally:
        if scoped_index and os.path.exists(scoped_index):
            os.remove(scoped_index)


def _plain(text):
    """Printable ASCII as-is; anything else JSON-escaped so it cannot drive the terminal."""
    text = str(text)
    if text.isascii() and text.isprintable():
        return text
    return json.dumps(text, ensure_ascii=True)


DESCRIPTION_LIMIT = 80


def describe(finding):
    """The rule's own description (ruleset text, never matched data), safe to print."""
    text = finding.get("description")
    if not isinstance(text, str):
        return ""
    return _plain(" ".join(text.split())[:DESCRIPTION_LIMIT])


def location(finding):
    """`file` or `file:LINE`, safe to print."""
    where = _plain(finding.get("File", "unknown file"))
    if type(finding.get("line")) is int:
        where += f":{finding['line']}"
    return where


def leftblock_version():
    try:
        from importlib.metadata import version
        return version("leftblock")
    except Exception:
        return "unknown"


def ruleset_id(config, repo_root):
    """sha256[:12] of the gitleaks config file a checker names with --config, else "unknown"."""
    checkers = config.get("checkers") if isinstance(config, dict) else None
    for checker in checkers if isinstance(checkers, list) else []:
        command = checker.get("command") if isinstance(checker, dict) else None
        if not isinstance(command, str):
            continue
        try:
            argv = shlex.split(command)
        except ValueError:
            continue
        for i, arg in enumerate(argv):
            if arg == "--config" and i + 1 < len(argv):
                path = argv[i + 1]
            elif arg.startswith("--config="):
                path = arg[len("--config="):]
            else:
                continue
            try:
                with open(os.path.join(repo_root, path), "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()[:12]
            except OSError:
                return "unknown"
    return "unknown"


def command_prefix():
    """How to invoke this LeftBlock in printed advice, without leaking a home path.

    Uses `leftblock` when that name on PATH runs this same installation;
    otherwise this interpreter with the home directory shortened to `~`.
    """
    here = os.path.dirname(os.path.abspath(sys.executable))
    found = shutil.which("leftblock")
    if found and os.path.dirname(os.path.realpath(found)) in (here, os.path.realpath(here)):
        return "leftblock"
    return shell_path(sys.executable) + " -I -B -m leftblock.cli"


def shell_path(path):
    """A shell-quoted path with the home directory shown as `~`."""
    path = os.path.abspath(path)
    home = os.path.expanduser("~")
    if home and path.startswith(home + os.sep):
        return "~/" + shlex.quote(path[len(home) + 1:])
    return shlex.quote(path)


_REMOVE_AND_ROTATE = "Remove it AND rotate the key: it may already be exposed."
_HOME_PATH = "Use a relative path, $HOME or ~ instead."
_DESCRIBE_ID = "Drop the identifier or describe it instead."
RULE_HINTS = {
    "leftblock-personal-email": "Use a role address or a reserved placeholder (example.com/.org/.net, or any .test, .example or .invalid domain), or describe it instead.",
    "leftblock-home-path-posix": _HOME_PATH,
    "leftblock-home-path-windows": _HOME_PATH,
    "leftblock-session-uuid": _DESCRIBE_ID,
    "leftblock-actor-id": _DESCRIBE_ID,
    "leftblock-openai-key": _REMOVE_AND_ROTATE,
    "leftblock-anthropic-key": _REMOVE_AND_ROTATE,
    "leftblock-groq-key": _REMOVE_AND_ROTATE,
    "leftblock-xai-key": _REMOVE_AND_ROTATE,
    "leftblock-replicate-key": _REMOVE_AND_ROTATE,
    "leftblock-together-key": _REMOVE_AND_ROTATE,
    "leftblock-openrouter-key": _REMOVE_AND_ROTATE,
    "leftblock-fireworks-key": _REMOVE_AND_ROTATE,
    "leftblock-cerebras-key": _REMOVE_AND_ROTATE,
    "leftblock-langsmith-key": _REMOVE_AND_ROTATE,
    "leftblock-elevenlabs-key": _REMOVE_AND_ROTATE,
    "leftblock-voyage-key": _REMOVE_AND_ROTATE,
    "leftblock-pinecone-key": _REMOVE_AND_ROTATE,
    "leftblock-ai-provider-key-assignment": _REMOVE_AND_ROTATE,
    "leftblock-eth-private-key": _REMOVE_AND_ROTATE,
    "leftblock-wif-key": _REMOVE_AND_ROTATE,
    "leftblock-bip39-mnemonic": _REMOVE_AND_ROTATE,
    bypass.MARKER_RULE: "Remove the marker and fix the content, or record a reasoned override.",
    bypass.IGNORE_RULE: "Don't suppress findings silently; record a reasoned override per finding.",
}
KANBUS_ISSUE_HINT = (
    "This issue file is written by Kanbus; fix the content with kbs update "
    "(or kbs comment), don't hand-edit it."
)
# Events are append-only history: kbs update/comment add a new event and leave
# the flagged text in place.
KANBUS_EVENT_HINT = (
    "This Kanbus event is append-only history and can't be edited. If the issue "
    "isn't committed yet, run kbs delete <issue id> and recreate it without the "
    "content; otherwise ask the board owner."
)
KANBUS_DATA = re.compile(r"(^|/)project/(issues|events)/[^/]+\.jsonl?$")


def print_failures(failures):
    for result in failures:
        print_warn(f"Checker {json.dumps(str(result.name))} did not pass.")
        if isinstance(result.findings, list):
            by_rule = {}
            for finding in result.findings:
                by_rule.setdefault(finding.get("RuleID", "finding"), []).append(finding)
            kanbus_files = []
            for rule, group in by_rule.items():
                for finding in group:
                    line = f"{location(finding)}: {_plain(rule)}"
                    if finding.get("id"):
                        line += f" [id {finding['id']}]"
                    if describe(finding):
                        line += f" ({describe(finding)})"
                    print("      " + line, file=sys.stderr)
                    name = finding.get("File")
                    if isinstance(name, str) and KANBUS_DATA.search(name) and name not in kanbus_files:
                        kanbus_files.append(name)
                if rule in RULE_HINTS:
                    print("      Hint: " + RULE_HINTS[rule], file=sys.stderr)
            for name in kanbus_files:
                hint = KANBUS_EVENT_HINT if KANBUS_DATA.search(name).group(2) == "events" else KANBUS_ISSUE_HINT
                print(f"      {_plain(name)}: {hint}", file=sys.stderr)
        else:
            print_warn(str(result.findings))


def default_local_policy(repo_root):
    """The local check-only policy file when one is installed, else None."""
    proc = run_cmd(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=False, cwd=repo_root,
    )
    if proc.returncode or not proc.stdout.strip():
        return None
    path = os.path.join(proc.stdout.strip(), "leftblock", "policy.json")
    return path if os.path.isfile(path) else None


def finding_summary(findings):
    """One-line list of rule, file and id, for callers that show only the last line."""
    parts = []
    for f in findings:
        part = f"{_plain(f.get('RuleID', 'finding'))} in {location(f)}"
        if f.get("id"):
            part += f" [id {f['id']}]"
        if part not in parts:
            parts.append(part)
    return "; ".join(parts)


def config_flag(repo_root, config_path):
    """` --config PATH` when the policy differs from the one `check` picks by default."""
    default = default_local_policy(repo_root) or os.path.join(repo_root, ".leftblock.yml")
    if config_path and os.path.abspath(config_path) != os.path.abspath(default):
        return f" --config {shell_path(config_path)}"
    return ""


def print_rerun(repo_root, config_path):
    print_info(f"Re-run this check: {command_prefix()} check{config_flag(repo_root, config_path)}")


def override_command(ids, repo_root, config_path):
    command = f"{command_prefix()} allow {' '.join(dict.fromkeys(ids))}"
    command += config_flag(repo_root, config_path)
    return command + ' --reason "<why this is not sensitive>"'


def print_override_instructions(failures, repo_root, config_path):
    # Tools that drive `git commit` often surface only the final line, so the
    # last ERROR line names every finding and the next step on its own.
    findings = [
        f for result in failures if isinstance(result.findings, list) for f in result.findings
    ]
    own = [f for f in findings if f.get("File") == allowlist.ALLOW_FILE]
    findings = [f for f in findings if f.get("File") != allowlist.ALLOW_FILE]
    ids = [f["id"] for f in findings if f.get("id")]
    steps = []
    if own:
        print_warn(
            f"A reason in {allowlist.ALLOW_FILE} contains a flagged value; "
            "reword that reason (don't repeat the value)."
        )
        steps.append(f"reword the flagged reason in {allowlist.ALLOW_FILE}")
    if len(ids) < len(findings):
        print_warn("Findings without an id cannot be overridden and must be removed.")
    if findings:
        steps.append("remove the flagged content")
    if ids:
        command = override_command(ids, repo_root, config_path)
        print_info(
            "An override adds the finding to .leftblock-allow.yml and stages it, so it "
            "appears in the commit and its review."
        )
        steps.append("if it is a false alarm, record a reviewed override: " + command)
    advice = "; or ".join(steps)
    print_rerun(repo_root, config_path)
    print_err(f"Inspection blocked: {finding_summary(own + findings)}. {advice[:1].upper()}{advice[1:]}.")


def cmd_allow(args):
    """Record reviewed overrides for current findings in .leftblock-allow.yml."""
    reason = " ".join((args.reason or "").split())
    if len(reason) < allowlist.MIN_REASON:
        print_err(f"--reason must explain the override (at least {allowlist.MIN_REASON} characters).")
        sys.exit(1)
    if args.deep:
        return cmd_allow_deep(args, reason)
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    config_path = args.config or default_local_policy(repo_root)
    tree_hash = get_tree_hash()
    _, results = configured_checks(repo_root, config_path, overrides=False)
    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed during inspection. Run it again.")
        sys.exit(1)
    if any(result.error for result in results):
        print_err("A checker could not complete. No override recorded.")
        sys.exit(1)
    current = {
        f["id"]: f for result in results if isinstance(result.findings, list)
        for f in result.findings if f.get("id")
    }
    unknown = [i for i in args.ids if i not in current]
    if unknown:
        print_err("Not a current finding id: " + ", ".join(json.dumps(i) for i in unknown))
        sys.exit(1)
    snapshot = allowlist.snapshot(repo_root)
    chosen = [current[i] for i in dict.fromkeys(args.ids)]
    for finding in chosen:
        finding["kind"] = describe(finding)
    try:
        added = allowlist.record_overrides(repo_root, chosen, reason)
    except (OSError, allowlist.AllowError):
        print_err(f"Existing {allowlist.ALLOW_FILE} is unreadable or invalid; fix it first.")
        sys.exit(1)
    run_cmd(["git", "add", "--", allowlist.ALLOW_FILE], cwd=repo_root)
    # A reason that repeats the flagged value would get the allow file flagged.
    _, after = configured_checks(repo_root, config_path, overrides=False)
    own = [
        f for result in after if isinstance(result.findings, list)
        for f in result.findings if f.get("File") == allowlist.ALLOW_FILE
    ]
    if own or any(result.error for result in after):
        allowlist.restore(repo_root, snapshot)
        if own:
            print_err(
                f"The reason would itself be flagged (rule {own[0].get('RuleID')}). "
                "Don't repeat the flagged value in the reason; describe it instead."
            )
        else:
            print_err("A checker could not complete. No override recorded.")
        sys.exit(1)
    for finding in added:
        print_info(f"Recorded override {finding['id']} for {finding['RuleID']} in {finding['File']}.")
    if not added:
        print_info("Those ids were already recorded.")
    print_info(f"{allowlist.ALLOW_FILE} is staged; the commit must include it.")


def json_report(result, findings, applied, errors, command):
    return {
        "version": leftblock_version(),
        "result": result,
        "findings": [dict({
            "file": f.get("File"), "line": f.get("line"), "rule": f.get("RuleID"),
            "id": f.get("id"), "description": f.get("description"),
        }, **({"score": round(f["score"], 2)} if "score" in f else {})) for f in findings],
        "overrides_applied": [
            {"file": f["File"], "rule": f["RuleID"], "id": f["id"], "reason": reason}
            for f, reason in applied
        ],
        "errors": [{"checker": checker, "message": message} for checker, message in errors],
        "override_command": command,
    }


def cmd_check(args):
    """Noninteractive staged inspection for existing pre-commit hook managers.

    Also the dry run of a commit: it inspects the staged changes with the same
    policy the hook uses and changes nothing. Exit status: 0 passed, 1 blocked
    by findings, 2 a checker or the configuration could not complete.
    """
    as_json = getattr(args, "format", "text") == "json"
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    config_path = getattr(args, "config", None)
    if config_path is None:
        config_path = default_local_policy(repo_root)

    def finish(code, result, findings=(), applied=(), errors=(), command=None):
        if as_json:
            print(json.dumps(json_report(result, findings, applied, errors, command), indent=2))
        if code:
            sys.exit(code)

    try:
        tree_hash = get_tree_hash()
    except UnmergedIndexError:
        print_err(UNMERGED_MESSAGE)
        finish(EXIT_ERROR, "error", errors=[("index", UNMERGED_MESSAGE)])
    try:
        warn_root_gitleaksignore(repo_root)
        config, results, applied = run_checks(repo_root, config_path)
    except ConfigError:
        print_err(CONFIG_ERROR)
        finish(EXIT_ERROR, "error", errors=[("configuration", CONFIG_ERROR)])
    failures = [result for result in results if not result.clean]
    findings = [
        f for result in failures if isinstance(result.findings, list) for f in result.findings
    ]
    errors = [(str(result.name), str(result.findings)) for result in failures if result.error]
    if failures:
        print_info(f"leftblock {leftblock_version()}, ruleset {ruleset_id(config, repo_root)}")
    print_applied(applied)
    if get_tree_hash() != tree_hash:
        message = "Staged tree changed during inspection. Check blocked; run it again."
        print_err(message)
        finish(EXIT_ERROR, "error", findings, applied, errors + [("inspection", message)])
    if failures:
        print_failures(failures)
        ids = [f["id"] for f in findings if f.get("id") and f.get("File") != allowlist.ALLOW_FILE]
        command = override_command(ids, repo_root, config_path) if ids else None
        if errors and not findings:
            problems = "; ".join(f"{name}: {message}" for name, message in errors)
            print_rerun(repo_root, config_path)
            print_err(f"Inspection blocked: {problems} Fix this first; no override is available.")
        else:
            print_override_instructions(failures, repo_root, config_path)
        finish(
            EXIT_ERROR if errors else EXIT_BLOCKED, "error" if errors else "blocked",
            findings, applied, errors, command,
        )
    print_info("All configured checks passed for staged changes.")
    finish(EXIT_PASSED, "passed", (), applied)


# --- Deep scan (optional, model-based) ---------------------------------------------

def add_deep_options(parser):
    parser.add_argument(
        "--labels", default="",
        help="Also report these comma-separated labels (off by default: "
             + ", ".join(deep.OPTIONAL_LABELS) + ")",
    )
    parser.add_argument(
        "--threshold", default=str(deep.DEFAULT_THRESHOLD),
        help="Minimum model score to report (default %(default)s)",
    )


def deep_options_flags(args):
    flags = ""
    if args.labels:
        flags += " --labels " + shlex.quote(args.labels)
    if args.threshold != str(deep.DEFAULT_THRESHOLD):
        flags += " --threshold " + shlex.quote(args.threshold)
    return flags


def deep_findings(args, revisions=None):
    """Deep-scan findings, or raise deep.DeepScanError. Prints the download notice."""
    labels = deep.parse_labels(args.labels)
    threshold = deep.parse_threshold(args.threshold)
    detector = deep.load_detector(print_info)
    top = run_cmd(["git", "rev-parse", "--show-toplevel"], check=False)
    if top.returncode:
        raise deep.DeepScanError("Not inside a Git repository.")
    repo_root = top.stdout.strip()
    additions = (
        deep.range_additions(repo_root, revisions) if revisions else deep.staged_additions(repo_root)
    )
    return repo_root, deep.scan(additions, detector, labels, threshold, KANBUS_DATA)


def deep_error_message(exc):
    if isinstance(exc, deep.ExtraMissing):
        return f"Deep scan needs the optional model extra: {deep.INSTALL_HINT}"
    return str(exc)


def cmd_deep_scan(args):
    """Opt-in model scan of staged additions (or of a commit range, for CI).

    Never run by the commit hook. Exit status as for check: 0 passed, 1
    findings, 2 the scan could not complete. Prints location, label, score and
    id only, never the matched value.
    """
    as_json = args.format == "json"

    def finish(code, result, findings=(), applied=(), errors=(), command=None):
        if as_json:
            print(json.dumps(json_report(result, findings, applied, errors, command), indent=2))
        if code:
            sys.exit(code)

    try:
        repo_root, findings = deep_findings(args, args.range)
        entries = allowlist.load_allowlist(repo_root)
    except allowlist.AllowError:
        message = f"Invalid {allowlist.ALLOW_FILE}; deep scan blocked."
        print_err(message)
        finish(EXIT_ERROR, "error", errors=[("leftblock-allow", message)])
    except (ValueError, deep.DeepScanError) as exc:
        message = deep_error_message(exc)
        print_err(message)
        finish(EXIT_ERROR, "error", errors=[("deep-scan", message)])
    result = CheckerResult("privacy-filter", not findings, findings or None)
    applied = allowlist.apply_allowlist([result], entries)
    findings = result.findings or []
    print_applied(applied)
    if findings:
        print_info(f"leftblock {leftblock_version()}, deep scan with {deep.MODEL}")
        print_warn("Deep scan found possible sensitive data (model output; review each).")
        for f in findings:
            print(f"      {location(f)}: {_plain(f['RuleID'])} [id {f['id']}] (score {f['score']:.2f})", file=sys.stderr)
        command = (
            "leftblock allow --deep" + deep_options_flags(args) + " "
            + " ".join(f["id"] for f in findings) + ' --reason "<why this is not sensitive>"'
        )
        if args.range:
            print_info("Fix the content, or record the override on a staged change: " + command)
        else:
            print_info("Fix the content, or record a reviewed override: " + command)
        finish(EXIT_BLOCKED, "blocked", findings, applied, command=command)
    print_info("Deep scan passed for " + ("commits in " + args.range if args.range else "staged changes") + ".")
    finish(EXIT_PASSED, "passed", (), applied)


# --- Scanning text outside git ------------------------------------------------------

def _scan_error(message):
    print_err(message)
    sys.exit(EXIT_ERROR)


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def cmd_scan(args):
    """Scan JSONL records (stdin) or files and directories with the shipped rules.

    Needs no repository. Exit status: 0 no findings, 1 findings, 2 error.
    Prints positions, rules and ids only, never the matched value. Recorded
    overrides are not applied.
    """
    if args.jsonl and args.paths:
        _scan_error("--jsonl reads records from standard input; do not also give paths.")
    if not args.jsonl and not args.paths:
        _scan_error("Give PATH... to scan, or --jsonl to read records from standard input.")
    if args.jsonl and args.format:
        _scan_error("--format applies to paths; --jsonl always prints one JSON finding per line.")
    if not args.deep and (args.labels or args.threshold is not None):
        _scan_error("--labels and --threshold apply to --deep.")
    try:
        labels = deep.parse_labels(args.labels)
        threshold = deep.parse_threshold(
            deep.DEFAULT_THRESHOLD if args.threshold is None else args.threshold
        )
    except ValueError as exc:
        _scan_error(str(exc))

    def detector_factory():
        return deep.load_detector(print_info)

    options = (detector_factory if args.deep else None, labels, threshold)
    previous = None
    try:
        previous = signal.signal(signal.SIGTERM, _raise_interrupt)
    except ValueError:  # not the main thread
        pass
    try:
        if args.jsonl:
            findings = scan.scan_records(scan.read_records(sys.stdin.buffer), *options)
        else:
            findings = scan.scan_paths(args.paths, *options, kanbus_data=KANBUS_DATA)
    except scan.ScanError as exc:
        _scan_error(str(exc))
    except deep.DeepScanError as exc:
        _scan_error(deep_error_message(exc))
    except KeyboardInterrupt:
        _scan_error("Interrupted.")
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)

    out = sys.stdout
    try:
        if args.jsonl:
            for f in findings:
                out.write(json.dumps({"id": f["file"], **{k: v for k, v in f.items() if k not in ("file", "line")}}) + "\n")
        elif args.format == "json":
            out.write(json.dumps({"findings": findings}, indent=2) + "\n")
        else:
            for f in findings:
                score = f" (score {f['score']:.2f})" if "score" in f else ""
                out.write(
                    f"{_plain(f['file'])}:{f['line']}: {_plain(f['rule'])} [id {f['finding_id']}] "
                    f"bytes {f['start']}-{f['end']}{score}\n"
                )
        out.flush()
    except BrokenPipeError:
        sys.stderr.close()
    if findings and not args.jsonl and args.format != "json":
        print_warn(f"{len(findings)} finding(s). Values are never printed; use the byte offsets to redact.")
    sys.exit(EXIT_BLOCKED if findings else EXIT_PASSED)


def cmd_allow_deep(args, reason):
    """leftblock allow --deep: record overrides for current deep-scan findings."""
    tree_hash = get_tree_hash()
    try:
        repo_root, findings = deep_findings(args)
    except (ValueError, deep.DeepScanError) as exc:
        print_err(deep_error_message(exc))
        sys.exit(EXIT_ERROR)
    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed during inspection. Run it again.")
        sys.exit(1)
    current = {f["id"]: f for f in findings}
    unknown = [i for i in args.ids if i not in current]
    if unknown:
        print_err("Not a current deep-scan finding id: " + ", ".join(json.dumps(i) for i in unknown))
        sys.exit(1)
    chosen = [current[i] for i in dict.fromkeys(args.ids)]
    for finding in chosen:
        finding["kind"] = describe(finding)
    try:
        added = allowlist.record_overrides(repo_root, chosen, reason)
    except (OSError, allowlist.AllowError):
        print_err(f"Existing {allowlist.ALLOW_FILE} is unreadable or invalid; fix it first.")
        sys.exit(1)
    run_cmd(["git", "add", "--", allowlist.ALLOW_FILE], cwd=repo_root)
    for finding in added:
        print_info(f"Recorded override {finding['id']} for {finding['RuleID']} in {finding['File']}.")
    if not added:
        print_info("Those ids were already recorded.")
    print_info(f"{allowlist.ALLOW_FILE} is staged; the commit must include it.")


def cmd_hook(args):
    """Run checkers on staged files and sign the commit."""
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()
    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'leftblock install' first.")
        sys.exit(1)

    try:
        tree_hash = get_tree_hash()
    except UnmergedIndexError:
        print_err(UNMERGED_MESSAGE)
        sys.exit(1)
    print_info(f"Scanning tree {tree_hash}...")

    warn_root_gitleaksignore(repo_root)
    try:
        config, results, applied = run_checks(repo_root)
    except ConfigError:
        print_err(CONFIG_ERROR)
        sys.exit(1)
    print_applied(applied)
    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed during inspection. Commit blocked; run the checks again.")
        sys.exit(1)

    all_clean = True
    failed_checkers = []
    for res in results:
        if not res.clean:
            all_clean = False
            failed_checkers.append(res)

    validator_str = f"leftblock-v{config.get('version', '1')}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if all_clean:
        # Staged, reasoned overrides need no passphrase but are not a clean pass.
        result_str = f"allowed:{len(applied)}" if applied else "clean"
        print_info("✓ All checks passed." if not applied else f"✓ All checks passed with {len(applied)} recorded override(s).")
    else:
        print_warn(f"✗ Found issues in {len(failed_checkers)} checker(s):")
        print_failures(failed_checkers)
        if any(result.error for result in failed_checkers):
            print_err("A checker could not complete. Commit blocked; fix the checker before retrying.")
            sys.exit(1)

        if not sys.stdin.isatty():
            print_err("Findings require human approval but no interactive terminal is available. Commit blocked.")
            sys.exit(1)

        print_warn("Commit will be blocked unless you approve these findings.")
        password = getpass.getpass(f"\033[1m[leftblock]\033[0m Enter approval passphrase to override: ").strip()

        if password != secret:
            print_err("Incorrect passphrase. Commit blocked.")
            sys.exit(1)

        result_str = f"override:{len(failed_checkers)}-checkers"
        print_info("✓ Override approved.")

    if get_tree_hash() != tree_hash:
        print_err("Staged tree changed before signing. Commit blocked; run the checks again.")
        sys.exit(1)
    hmac_sig = compute_hmac(tree_hash, validator_str, result_str, timestamp, secret)

    # Append trailers
    msg_file = args.commit_msg_file
    with open(msg_file, 'r') as f:
        msg_content = f.read()

    proc = subprocess.run(
        ["git", "interpret-trailers",
         f"--trailer=Inspected-by: {validator_str}",
         f"--trailer=Inspection-tree: {tree_hash}",
         f"--trailer=Inspection-result: {result_str}",
         f"--trailer=Inspection-at: {timestamp}",
         f"--trailer=Inspection-sig: hmac-sha256:{hmac_sig}"],
        input=msg_content, text=True, capture_output=True, check=True
    )

    with open(msg_file, 'w') as f:
        f.write(proc.stdout)

    print_info(f"✓ Commit signed: hmac-sha256:{hmac_sig[:16]}...")

def cmd_approve(args):
    """Retroactively approve commits by generating a paperwork commit."""
    repo_root = run_cmd(["git", "rev-parse", "--show-toplevel"]).stdout.strip()

    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'leftblock install'.")
        sys.exit(1)

    range_str = args.range
    if ".." in range_str:
        commits = run_cmd(["git", "rev-list", "--reverse", range_str]).stdout.splitlines()
    else:
        commits = [run_cmd(["git", "rev-parse", range_str]).stdout.strip()]

    if not commits:
        print_info("No commits found in range.")
        sys.exit(0)

    try:
        config = load_config(repo_root)
        checkers = validate_checkers(config)
    except (OSError, ValueError, yaml.YAMLError):
        print_err("Missing or invalid checker configuration. Approval blocked.")
        sys.exit(1)

    validator_str = f"leftblock-v{config.get('version', '1')}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    trailers = []

    for sha in commits:
        short = sha[:7]
        print_info(f"Checking commit {short}...")
        actual_tree = get_commit_tree_hash(sha)

        # Set up a worktree for the commit
        import tempfile
        wt_dir = tempfile.mkdtemp()
        run_cmd(["git", "worktree", "add", "--detach", wt_dir, sha])

        try:
            # We want to scan the diff introduced by this commit, so we soft reset to its parent.
            parent = run_cmd(["git", "rev-parse", f"{sha}~1"], check=False).stdout.strip()
            if not parent:
                # Root commit
                empty_tree = run_cmd(["git", "hash-object", "-t", "tree", "/dev/null"]).stdout.strip()
                run_cmd(["git", "reset", "--soft", empty_tree], cwd=wt_dir)
            else:
                run_cmd(["git", "reset", "--soft", parent], cwd=wt_dir)

            results = execute_checkers(checkers, cwd=wt_dir)
        finally:
            run_cmd(["git", "worktree", "remove", "-f", wt_dir])

        all_clean = True
        failed_checkers = []
        for res in results:
            if not res.clean:
                all_clean = False
                failed_checkers.append(res)

        if all_clean:
            result_str = "clean"
        else:
            print_warn(f"✗ Found issues in {short} for {len(failed_checkers)} checker(s).")
            if any(result.error for result in failed_checkers):
                print_err("A checker could not complete. Approval blocked.")
                sys.exit(1)
            if not sys.stdin.isatty():
                print_err("Findings require human approval but no interactive terminal is available. Approval blocked.")
                sys.exit(1)

            password = getpass.getpass(f"\033[1m[leftblock]\033[0m Enter approval passphrase to override for {short}: ").strip()
            if password != secret:
                print_err("Incorrect passphrase. Approval blocked.")
                sys.exit(1)
            result_str = f"override:{len(failed_checkers)}-checkers"

        hmac_sig = compute_hmac(actual_tree, validator_str, result_str, timestamp, secret)

        trailers.append(f"--trailer=Inspected-by: {validator_str}")
        trailers.append(f"--trailer=Inspection-tree: {actual_tree}")
        trailers.append(f"--trailer=Inspection-result: {result_str}")
        trailers.append(f"--trailer=Inspection-at: {timestamp}")
        trailers.append(f"--trailer=Inspection-sig: hmac-sha256:{hmac_sig}")

    # Create the approval commit
    commit_msg = "chore: retroactive leftblock approval\n"
    cmd = ["git", "commit", "--allow-empty", "-F", "-"] + trailers
    proc = subprocess.run(cmd, input=commit_msg, text=True, capture_output=True, check=True)
    print_info(f"Created approval commit:\n{proc.stdout.strip()}")

def cmd_verify(args):
    """Verify signatures for a commit range."""
    try:
        secret = get_secret()
    except FileNotFoundError:
        print_err("Shared secret not found. Run 'leftblock install'.")
        sys.exit(1)

    range_str = args.range
    if ".." in range_str:
        commits = run_cmd(["git", "rev-list", range_str]).stdout.splitlines()
    else:
        commits = [run_cmd(["git", "rev-parse", range_str]).stdout.strip()]

    # Pool all valid signatures found in the range
    valid_trees = set()

    for sha in commits:
        # Get all trailers from the commit message
        msg = run_cmd(["git", "log", "-1", sha, "--format=%B"]).stdout
        # Basic parsing of trailers. git log format for multiple identical keys is tricky,
        # so we parse the raw message.
        import re
        trees = re.findall(r"^Inspection-tree:\s*(.+)$", msg, re.MULTILINE)
        sigs = re.findall(r"^Inspection-sig:\s*hmac-sha256:(.+)$", msg, re.MULTILINE)
        validators = re.findall(r"^Inspected-by:\s*(.+)$", msg, re.MULTILINE)
        results = re.findall(r"^Inspection-result:\s*(.+)$", msg, re.MULTILINE)
        timestamps = re.findall(r"^Inspection-at:\s*(.+)$", msg, re.MULTILINE)

        # Zip them up (assuming they appear in blocks)
        for t, s, v, r, ts in zip(trees, sigs, validators, results, timestamps):
            expected = compute_hmac(t, v, r, ts, secret)
            if s == expected:
                valid_trees.add(t)

    failures = 0
    for sha in commits:
        short = sha[:7]
        actual_tree = get_commit_tree_hash(sha)

        if actual_tree not in valid_trees:
            print_err(f"{short}: No valid signature found for tree {actual_tree[:12]}.")
            failures += 1
            continue

        subject = run_cmd(["git", "log", "-1", sha, "--format=%s"]).stdout.strip()[:50]
        print(f"\033[1;32mPASS:\033[0m {short}: {subject} [verified]")

    if failures > 0:
        print_err(f"Verification failed: {failures}/{len(commits)} commit(s) invalid.")
        sys.exit(1)
    else:
        print(f"\033[1;32mAll {len(commits)} commit(s) verified.\033[0m")

def main():
    parser = argparse.ArgumentParser(description="LeftBlock - A pluggable inspection gate for Git commits")
    parser.add_argument("--version", action="version", version=f"leftblock {leftblock_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_p = subparsers.add_parser("install", help="Install the commit-msg hook and setup secrets")
    install_p.add_argument("--local", action="store_true", help="Keep policy in the common Git directory (with --check-only)")
    install_p.add_argument("--check-only", action="store_true", help="Install a pre-commit check without signing (with --local)")
    install_p.add_argument("--gitleaks", help="Existing Gitleaks executable for a local check-only installation")

    check_p = subparsers.add_parser("check", help="Inspect staged changes without signing")
    check_p.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="With json, also print one JSON result object on stdout (stderr is unchanged)",
    )
    check_p.add_argument("--config", help="Checker policy; defaults to the local install policy when present, else .leftblock.yml")

    allow_p = subparsers.add_parser("allow", help="Record a reviewed override for current findings")
    allow_p.add_argument("ids", nargs="+", metavar="ID", help="Finding id(s) shown by the blocked check")
    allow_p.add_argument("--reason", default=None, help="Why the finding is not sensitive")
    allow_p.add_argument("--config", help="Checker policy; defaults to the local install policy, else .leftblock.yml")
    allow_p.add_argument("--deep", action="store_true", help="IDs are deep-scan findings (takes --labels and --threshold)")
    add_deep_options(allow_p)

    deep_p = subparsers.add_parser(
        "deep-scan", help="Optional model-based scan of staged additions or a commit range (needs leftblock[deep])",
    )
    deep_p.add_argument("--range", metavar="A..B", help="Scan the added lines of the commits in this range (for CI) instead of the staged diff")
    deep_p.add_argument("--format", choices=["text", "json"], default="text", help="With json, also print one JSON result object on stdout")
    add_deep_options(deep_p)

    scan_p = subparsers.add_parser(
        "scan",
        help="Scan text outside git (JSONL records on stdin, or files and directories) with the shipped rules",
        description="Scan text that is not in a Git repository with the same rules and post-filters as the "
                    "commit hook. Prints byte offsets, rules and finding ids, never the matched value. "
                    "Recorded overrides (.leftblock-allow.yml) are not applied. Exit status: 0 no "
                    "findings, 1 findings, 2 error.",
    )
    scan_p.add_argument("paths", nargs="*", metavar="PATH", help="Files or directories to scan (recursive)")
    scan_p.add_argument(
        "--jsonl", action="store_true",
        help='Read records {"id": "...", "text": "..."} one per line from standard input; print one JSON '
             'finding per line with UTF-8 byte offsets into the record text',
    )
    scan_p.add_argument("--format", choices=["text", "json"], help="Output for paths (default text)")
    scan_p.add_argument("--deep", action="store_true", help="Also run the Privacy Filter model (needs leftblock[deep])")
    scan_p.add_argument("--labels", default="", help="With --deep, also report these comma-separated labels (off by default: "
                        + ", ".join(deep.OPTIONAL_LABELS) + ")")
    scan_p.add_argument("--threshold", default=None, help="With --deep, minimum model score (default %s)" % deep.DEFAULT_THRESHOLD)

    hook_p = subparsers.add_parser("hook", help="Run checkers (used internally by git hook)")
    hook_p.add_argument("commit_msg_file", help="Path to the commit message file")

    verify_p = subparsers.add_parser("verify", help="Verify commits")
    verify_p.add_argument("range", nargs="?", default="HEAD", help="Commit range (e.g. HEAD~3..HEAD)")

    approve_p = subparsers.add_parser("approve", help="Retroactively approve commits")
    approve_p.add_argument("range", help="Commit range to approve")

    args = parser.parse_args()

    if args.command == "install":
        cmd_install(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "allow":
        cmd_allow(args)
    elif args.command == "deep-scan":
        cmd_deep_scan(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "hook":
        cmd_hook(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "approve":
        cmd_approve(args)

if __name__ == "__main__":
    main()
