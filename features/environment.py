"""Behave hooks: every scenario runs inside its own disposable world.

Before each scenario a temporary root is created holding a temporary HOME and
a temporary LEFTBLOCK_HOME, so no scenario can ever touch the real ~/.local or
~/.config. The environment every subprocess must use is in ``context.env``.

Scenarios tagged ``@gitleaks`` are skipped when no gitleaks binary is on PATH.
"""

import os
import shutil
import subprocess
import sys
import tempfile

FEATURES_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(FEATURES_DIR)

# Step modules import the synthetic value registry as ``synthetic_data``.
if FEATURES_DIR not in sys.path:
    sys.path.insert(0, FEATURES_DIR)


def before_scenario(context, scenario):
    if "gitleaks" in scenario.effective_tags and shutil.which("gitleaks") is None:
        scenario.skip("gitleaks binary not installed")
        return

    context.root = tempfile.mkdtemp(prefix="leftblock-spec-")
    context.home = os.path.join(context.root, "home")
    context.leftblock_home = os.path.join(context.root, "leftblock-home")
    context.secret_path = os.path.join(context.home, ".config", "leftblock", "secret")
    os.makedirs(context.home)
    os.makedirs(context.leftblock_home)

    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "HOME": context.home,
        "LEFTBLOCK_HOME": context.leftblock_home,
        "LEFTBLOCK_SECRET_PATH": context.secret_path,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "NO_COLOR": "1",
        "PYTHONPATH": PROJECT_ROOT,
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    context.env = env
    context.repo = None
    context.result = None
    context.synthetic_values = []


def stop_privacy_filter_server(context):
    """Stop any resident Privacy Filter server the scenario started, so none outlives it."""
    if "XDG_RUNTIME_DIR" not in getattr(context, "env", {}):
        return
    subprocess.run(
        [sys.executable, "-m", "leftblock.cli", "deep-server", "stop"],
        env=context.env, cwd=context.root, capture_output=True, timeout=60,
    )


def after_scenario(context, scenario):
    if getattr(context, "root", None):
        stop_privacy_filter_server(context)
    root = getattr(context, "root", None)
    if root and os.path.exists(root):
        shutil.rmtree(root, ignore_errors=True)
    context.root = None
