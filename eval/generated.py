"""The generated LeftBlock corpus: realistic fake credentials planted in varied files.

CredData has no modern AI-provider keys, so this builds them. Every value is
assembled at run time from a seeded RNG (prefixes are split in the source so
no line here is key-shaped, and nothing generated is ever committed). The
corpus is written under the data directory, outside any repository.

Each file holds one planted credential (or an AWS pair) among ordinary
boilerplate, in one of eight contexts (.py .ts .env YAML JSON Markdown .ipynb
shell), in two flavours:

  named  the variable is named for the provider (``OPENAI_API_KEY``)
  bare   a neutral name with none of gitleaks' generic keywords, so only the
         key's own shape can give it away

Hard negatives (label F) are placeholders, UUIDs, hashes, documented example
values and environment-variable references, in the same contexts.
"""

import base64
import json
import os
import random
import string

from eval import scoring

ALNUM = string.ascii_letters + string.digits
LOWER = string.ascii_lowercase
LOWER_ALNUM = string.ascii_lowercase + string.digits
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"
UPPER_B32 = string.ascii_uppercase + "234567"
B64 = ALNUM + "+/"
PASSWORD_CHARS = ALNUM + "!@^*-_+="

CONTEXTS = ("py", "ts", "env", "yaml", "json", "md", "ipynb", "sh")
NEUTRAL_NAMES = ("payload", "blob", "ref", "value", "data")


def tok(rng, n, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(n))


# --- Value builders: (rng) -> value ----------------------------------------------

def _openai(rng):
    mark = "T3Blbk" + "FJ"
    style = rng.choice(["proj74", "proj58", "legacy"])
    if style == "legacy":
        return "sk" + "-" + tok(rng, 20) + mark + tok(rng, 20)
    n = 74 if style == "proj74" else 58
    return "sk" + "-proj-" + tok(rng, n, URLSAFE) + mark + tok(rng, n, URLSAFE)


def _openai_admin(rng):
    mark = "T3Blbk" + "FJ"
    return "sk" + "-admin-" + tok(rng, 74, URLSAFE) + mark + tok(rng, 74, URLSAFE)


def _anthropic(rng):
    return "sk" + "-ant-" + rng.choice(["api03-", "admin01-"]) + tok(rng, 93, URLSAFE) + "AA"


def _github(rng):
    if rng.random() < 0.3:
        return "github" + "_pat_" + tok(rng, 22) + "_" + tok(rng, 59)
    return "gh" + rng.choice("pousr") + "_" + tok(rng, 36)


def _slack(rng):
    style = rng.choice(["bot", "user", "app", "hook"])
    digits = "0123456789"
    if style == "app":
        return "xapp" + "-1-A" + tok(rng, 10, string.ascii_uppercase + digits) + "-" + tok(rng, 13, digits) + "-" + tok(rng, 64, HEX)
    if style == "hook":
        return ("https://hooks." + "slack.com/services/T" + tok(rng, 10, string.ascii_uppercase + digits)
                + "/B" + tok(rng, 10, string.ascii_uppercase + digits) + "/" + tok(rng, 24))
    return "xox" + ("b" if style == "bot" else "p") + "-" + tok(rng, 12, digits) + "-" + tok(rng, 12, digits) + "-" + tok(rng, 24)


def _stripe(rng):
    return rng.choice(["sk", "rk"]) + "_live_" + tok(rng, 24)


def _jwt(rng):
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    header = enc({"alg": rng.choice(["HS256", "RS256"]), "typ": "JWT"})
    payload = enc({"sub": tok(rng, 12, string.digits), "name": tok(rng, 6, LOWER).title(),
                   "iat": rng.randint(1_600_000_000, 1_790_000_000), "scope": "read write"})
    return header + "." + payload + "." + tok(rng, 43, URLSAFE)


def _db_url(rng):
    scheme = rng.choice(["postgresql", "mysql", "mongodb", "redis", "amqp"])
    user = tok(rng, 8, LOWER)
    password = tok(rng, 16, ALNUM)
    host = tok(rng, 10, LOWER_ALNUM) + ".cluster-" + tok(rng, 12, LOWER_ALNUM) + ".us-east-1.rds.amazonaws.com"
    port = {"postgresql": 5432, "mysql": 3306, "mongodb": 27017, "redis": 6379, "amqp": 5672}[scheme]
    return "%s://%s:%s@%s:%d/%s" % (scheme, user, password, host, port, tok(rng, 8, LOWER))


def _password(rng):
    return tok(rng, 1) + tok(rng, rng.randint(11, 17), PASSWORD_CHARS)


def _pem(rng):
    label = rng.choice(["RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY"])
    rows = 6 if label == "EC PRIVATE KEY" else 25
    body = [tok(rng, 64, B64) for _ in range(rows)] + [tok(rng, rng.randint(8, 60), B64)]
    body[0] = rng.choice(["MIIE", "MIIB", "b3Bl"]) + body[0][4:]
    return "\n".join(["-----BEGIN " + label + "-----"] + body + ["-----END " + label + "-----"])


# kind -> (category, builder, named variable, placeholder prefix, bare allowed)
KINDS = {
    "openai": ("OpenAI key", _openai, "OPENAI_API_KEY", "sk-", True),
    "openai-admin": ("OpenAI admin key", _openai_admin, "OPENAI_ADMIN_KEY", "sk-admin-", True),
    "anthropic": ("Anthropic key", _anthropic, "ANTHROPIC_API_KEY", "sk-ant-api03-", True),
    "groq": ("Groq key", lambda r: "gs" + "k_" + tok(r, 52), "GROQ_API_KEY", "gsk_", True),
    "xai": ("xAI key", lambda r: "xa" + "i-" + tok(r, 80), "XAI_API_KEY", "xai-", True),
    "replicate": ("Replicate key", lambda r: "r8" + "_" + tok(r, 37), "REPLICATE_API_TOKEN", "r8_", True),
    "together": ("Together AI key", lambda r: "tgp" + "_v1_" + tok(r, 43, URLSAFE), "TOGETHER_API_KEY", "tgp_v1_", True),
    "openrouter": ("OpenRouter key", lambda r: "sk" + "-or-v1-" + tok(r, 64, HEX), "OPENROUTER_API_KEY", "sk-or-v1-", True),
    "fireworks": ("Fireworks key", lambda r: "fw" + "_" + tok(r, 24), "FIREWORKS_API_KEY", "fw_", True),
    "cerebras": ("Cerebras key", lambda r: "cs" + "k-" + tok(r, 48, LOWER_ALNUM), "CEREBRAS_API_KEY", "csk-", True),
    "langsmith": ("LangSmith key", lambda r: "lsv2" + "_pt_" + tok(r, 32, HEX) + "_" + tok(r, 10, HEX), "LANGSMITH_API_KEY", "lsv2_pt_", True),
    "elevenlabs": ("ElevenLabs key", lambda r: "sk" + "_" + tok(r, 48, HEX), "ELEVENLABS_API_KEY", "sk_", True),
    "voyage": ("Voyage AI key", lambda r: "pa" + "-" + tok(r, 43, URLSAFE), "VOYAGE_API_KEY", "pa-", True),
    "pinecone": ("Pinecone key", lambda r: "pcs" + "k_" + tok(r, 6) + "_" + tok(r, 60), "PINECONE_API_KEY", "pcsk_", True),
    "mistral": ("Mistral key", lambda r: tok(r, 32), "MISTRAL_API_KEY", "", False),
    "cohere": ("Cohere key", lambda r: tok(r, 40), "COHERE_API_KEY", "", False),
    "azure-openai": ("Azure OpenAI key", lambda r: tok(r, 32, HEX), "AZURE_OPENAI_API_KEY", "", False),
    "deepgram": ("Deepgram key", lambda r: tok(r, 40, HEX), "DEEPGRAM_API_KEY", "", False),
    "together-legacy": ("Together AI legacy key", lambda r: tok(r, 64, HEX), "TOGETHER_API_KEY", "", False),
    "aws-access": ("AWS access key", lambda r: "AK" + "IA" + tok(r, 16, UPPER_B32), "AWS_ACCESS_KEY_ID", "AKIA", True),
    "aws-secret": ("AWS secret key", lambda r: tok(r, 40, B64), "AWS_SECRET_ACCESS_KEY", "", False),
    "github": ("GitHub token", _github, "GITHUB_TOKEN", "ghp_", True),
    "slack": ("Slack token", _slack, "SLACK_BOT_TOKEN", "xoxb-", True),
    "google": ("Google API key", lambda r: "AI" + "za" + tok(r, 35, URLSAFE), "GOOGLE_API_KEY", "AIza", True),
    "stripe": ("Stripe key", _stripe, "STRIPE_SECRET_KEY", "sk_live_", True),
    "pem": ("PEM private key", _pem, "PRIVATE_KEY", "-----BEGIN", True),
    "jwt": ("JWT", _jwt, "AUTH_TOKEN", "eyJ", True),
    "db-url": ("Database URL password", _db_url, "DATABASE_URL", "postgresql://", True),
    "password": ("Password assignment", _password, "DB_PASSWORD", "", False),
}


class Entry:
    def __init__(self, kind, value, var):
        self.kind = kind
        self.value = value
        self.var = var
        self.multiline = "\n" in value


# --- Contexts ----------------------------------------------------------------------
# Each renderer turns an Entry into the lines that carry it; ``wrap`` builds the file.

def _camel(name):
    parts = name.lower().split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _py(e, rng):
    if e.multiline:
        return ['%s = """' % e.var] + e.value.split("\n") + ['"""']
    return [rng.choice([
        '%s = "%s"' % (e.var, e.value),
        'client = make_client(%s="%s")' % (e.var.lower(), e.value),
        'SETTINGS = {"%s": "%s"}' % (e.var.lower(), e.value),
    ])]


def _ts(e, rng):
    if e.multiline:
        return ["export const %s = `" % _camel(e.var)] + e.value.split("\n") + ["`;"]
    return [rng.choice([
        'const %s = "%s";' % (_camel(e.var), e.value),
        'export const config = { %s: "%s" };' % (_camel(e.var), e.value),
        'const client = new Client({ %s: "%s" });' % (_camel(e.var), e.value),
    ])]


def _env(e, rng):
    name = e.var.upper()
    if e.multiline:
        return ['%s="%s"' % (name, e.value.replace("\n", "\\n"))]
    return [rng.choice(['%s=%s' % (name, e.value), '%s="%s"' % (name, e.value), 'export %s=%s' % (name, e.value)])]


def _yaml(e, rng):
    name = e.var.lower()
    if e.multiline:
        return ["  %s: |" % name] + ["    " + line for line in e.value.split("\n")]
    return ["  " + rng.choice(['%s: %s' % (name, e.value), '%s: "%s"' % (name, e.value)])]


def _json(e, rng):
    return ['  "%s": "%s",' % (e.var.lower(), e.value.replace("\n", "\\n"))]


def _md(e, rng):
    if e.multiline:
        return ["```"] + e.value.split("\n") + ["```"]
    return ["```bash", rng.choice(['export %s="%s"' % (e.var.upper(), e.value), '%s=%s ./run.sh' % (e.var.upper(), e.value)]), "```"]


def _sh(e, rng):
    if e.multiline:
        return ["cat > key.pem <<'EOF'"] + e.value.split("\n") + ["EOF"]
    return [rng.choice([
        'export %s="%s"' % (e.var.upper(), e.value),
        'curl -s -H "X-Api-Key: %s" https://api.service.invalid/v1/ping' % e.value,
        '%s=%s ./run.sh' % (e.var.upper(), e.value),
    ])]


def wrap(ctx, body, rng):
    """Surround ``body`` lines with ordinary content for the context; return the file text."""
    tag = tok(rng, 5, LOWER)
    if ctx == "py":
        lines = ["import os", "import logging", "", "log = logging.getLogger(__name__)", ""] + body + ["", "def main():", "    log.info('%s ready')" % tag, ""]
    elif ctx == "ts":
        lines = ["import { Client } from './client';", ""] + body + ["", "export function main(): void {", "  console.log('%s ready');" % tag, "}", ""]
    elif ctx == "env":
        lines = ["# local settings", "DEBUG=true", "PORT=8080", "NAME=%s" % tag] + body + ["LOG_LEVEL=info", ""]
    elif ctx == "yaml":
        lines = ["version: 1", "service:", "  name: %s" % tag, "  replicas: 2"] + body + ["  log_level: info", ""]
    elif ctx == "json":
        lines = ["{", '  "name": "%s",' % tag, '  "version": "1.0.0",'] + body + ['  "debug": false', "}", ""]
    elif ctx == "md":
        lines = ["# Setup notes", "", "Configure the %s service before the first run." % tag, ""] + body + ["", "Then start the service.", ""]
    elif ctx == "sh":
        lines = ["#!/usr/bin/env bash", "set -euo pipefail", "", "# %s deploy helper" % tag, ""] + body + ["", "echo done", ""]
    else:
        raise ValueError(ctx)
    return "\n".join(lines)


def notebook(body, rng):
    """A Jupyter notebook whose one code cell holds ``body`` (secret lines become JSON string lines)."""
    source = ["import os\n", "\n"] + [line + "\n" for line in body] + ["print('%s')" % tok(rng, 5, LOWER)]
    cell = {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": source}
    return json.dumps({"cells": [cell], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1) + "\n"


RENDER = {"py": _py, "ts": _ts, "env": _env, "yaml": _yaml, "json": _json, "md": _md, "sh": _sh, "ipynb": _py}
FILENAME = {"py": "app.py", "ts": "app.ts", "env": ".env", "yaml": "config.yml", "json": "settings.json",
            "md": "README.md", "ipynb": "notes.ipynb", "sh": "deploy.sh"}


def locate(text, value):
    """1-based (first, last) line numbers of ``value`` in ``text`` (None when absent)."""
    lines = text.split("\n")
    head, tail = value.split("\n")[0], value.split("\n")[-1]
    first = next((i for i, line in enumerate(lines) if head in line), None)
    if first is None:
        return None
    last = next((i for i in range(first, len(lines)) if tail in lines[i]), first)
    return first + 1, last + 1


# --- Negatives ---------------------------------------------------------------------

NEGATIVE_KINDS = ("placeholder", "uuid", "hash", "example", "env-ref")


def _uuid(rng):
    return "-".join([tok(rng, 8, HEX), tok(rng, 4, HEX), "4" + tok(rng, 3, HEX), rng.choice("89ab") + tok(rng, 3, HEX), tok(rng, 12, HEX)])


def negative(negkind, kind, rng):
    """(category, Entry or raw line list) for one hard negative imitating ``kind``."""
    category, _, var, prefix, _ = KINDS[kind]
    if negkind == "placeholder":
        value = rng.choice(["YOUR_API_KEY_HERE", "<your-api-key>", "changeme", "REPLACE_ME", "xxxxxxxxxxxxxxxxxxxxxxxx",
                            prefix + "x" * 24 if prefix and prefix != "-----BEGIN" else "your-key-here",
                            prefix + "..." if prefix and prefix != "-----BEGIN" else "<paste key here>"])
        return category, Entry(kind, value, var)
    if negkind == "uuid":
        return "UUID", Entry(kind, _uuid(rng), rng.choice(["trace_id", "request_id", "user_id", "correlation_id"]))
    if negkind == "hash":
        value = rng.choice([tok(rng, 64, HEX), tok(rng, 40, HEX), tok(rng, 32, HEX), "sha512-" + tok(rng, 86, B64) + "=="])
        return "Hash", Entry(kind, value, rng.choice(["checksum", "commit_sha", "integrity", "digest"]))
    if negkind == "example":
        if kind == "aws-access":
            value = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
        elif kind == "aws-secret":
            value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLE" + "KEY"
        else:
            value = rng.choice(["example", "example-api-key", "test-password", "dummy-token-value"])
        return category, Entry(kind, value, var)
    if negkind == "env-ref":
        return category, Entry(kind, rng.choice(["${%s}" % var, "$" + var, "${{ secrets.%s }}" % var]), var)
    raise ValueError(negkind)


def _env_reference_lines(ctx, e, rng):
    """Code-style references (``os.environ[...]``) where the context has code."""
    name = e.var
    forms = {
        "py": ['%s = os.environ["%s"]' % (name.lower(), name), '%s = os.getenv("%s")' % (name.lower(), name)],
        "ts": ["const %s = process.env.%s;" % (_camel(name), name)],
    }
    return forms.get(ctx)


# --- Corpus ------------------------------------------------------------------------

def generate(root, seed, copies=1):
    """Write the corpus under ``root`` and return ``(units, counts)``.

    ``units`` are ``scoring.Unit``s keyed by file path relative to ``root``;
    nothing about the values is returned. Deterministic for a given seed.
    """
    rng = random.Random(seed)
    units, serial = [], 0

    def emit(ctx, entries_lines, planted):
        """Write one file; ``planted`` is [(Entry, truth, category, tags)]."""
        nonlocal serial
        serial += 1
        body = []
        for lines in entries_lines:
            body.extend(lines)
        text = notebook(body, rng) if ctx == "ipynb" else wrap(ctx, body, rng)
        relative = os.path.join("generated", ctx, "%04d" % serial, FILENAME[ctx])
        target = os.path.join(root, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(text)
        for entry, truth, category, tags in planted:
            where = locate(text, entry.value)
            if where is None:
                raise RuntimeError("planted value not found in its own file (context %s)" % ctx)
            units.append(scoring.make_unit(relative, where[0], where[1], truth, [category], tags))

    for _ in range(copies):
        for kind, (category, build, named, _, bare_ok) in KINDS.items():
            for ctx in CONTEXTS:
                for flavour in ("named", "bare") if bare_ok else ("named",):
                    var = named if flavour == "named" else rng.choice(NEUTRAL_NAMES)
                    entry = Entry(kind, build(rng), var)
                    emit(ctx, [RENDER[ctx](entry, rng)], [(entry, "T", category, {"context": ctx, "flavour": flavour})])
        for negkind in NEGATIVE_KINDS:
            for ctx in CONTEXTS:
                for kind in rng.sample(sorted(KINDS), 3):
                    category, entry = negative(negkind, kind, rng)
                    lines = None
                    if negkind == "env-ref":
                        lines = _env_reference_lines(ctx, entry, rng)
                    if lines is None:
                        lines = RENDER[ctx](entry, rng)
                        locate_value = entry.value
                    else:
                        locate_value = entry.var
                        entry = Entry(kind, locate_value, entry.var)
                    emit(ctx, [lines], [(entry, "F", category, {"context": ctx, "negkind": negkind})])
    return units, {"files": serial}
