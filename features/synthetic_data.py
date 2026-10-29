"""Synthetic sensitive values for the specs.

Nothing in this module is a real credential, address or identifier, and no
line is shaped like one: every value is assembled at run time from a seeded
RNG (seeded by the kind name, so a kind always yields the same value). The
repository's own pre-commit hook and CI self-scan therefore stay clean.

A generator takes a ``random.Random`` and returns ``(content, values)``:
the text to write into a file (newline terminated) and the list of secret
strings that no LeftBlock output may ever reveal.

Register a new kind from a chapter's step module::

    from synthetic_data import generator, token

    @generator("my new kind")
    def _my_kind(rng):
        value = token(rng, 20)
        return "setting = %s\\n" % value, [value]

Kind names are matched exactly as written in the feature file and must be
unique across the suite.
"""

import hashlib
import string

GENERATORS = {}

ALNUM = string.ascii_letters + string.digits
LOWER = string.ascii_lowercase
LOWER_ALNUM = string.ascii_lowercase + string.digits
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
UPPER_BASE32 = string.ascii_uppercase + "234567"

# Subset of the BIP-39 wordlist (3-8 letters), enough to look like a phrase.
WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "across", "action", "actor", "actual",
    "adapt", "address", "adjust", "admit", "advance", "advice", "afford",
]


def token(rng, length, alphabet=ALNUM):
    """A random string of ``length`` characters drawn from ``alphabet``."""
    return "".join(rng.choice(alphabet) for _ in range(length))


def base58check(payload):
    """``payload`` plus its 4-byte double-SHA-256 checksum, base58-encoded."""
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, out = int.from_bytes(raw, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        out = BASE58[rest] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def wif(rng, compressed=True, version=0x80):
    """A syntactically valid WIF built from random bytes (never a real key)."""
    key = bytes(rng.randrange(256) for _ in range(32))
    return base58check(bytes([version]) + key + (b"\x01" if compressed else b""))


def bad_checksum(value):
    """``value`` with its last character changed, which breaks a base58check checksum."""
    return value[:-1] + ("2" if value[-1] != "2" else "3")


def uuid4(rng):
    """A random version-4 UUID string."""
    return "-".join([
        token(rng, 8, HEX), token(rng, 4, HEX), "4" + token(rng, 3, HEX),
        rng.choice("89ab") + token(rng, 3, HEX), token(rng, 12, HEX),
    ])


def generator(kind):
    """Decorator registering ``fn(rng) -> (content, values)`` under ``kind``."""
    def register(fn):
        if kind in GENERATORS:
            raise ValueError("duplicate synthetic kind: %r" % kind)
        GENERATORS[kind] = fn
        return fn
    return register


def make(kind, rng):
    """Build ``(content, values)`` for ``kind``; fail clearly when unknown."""
    if kind not in GENERATORS:
        raise KeyError(
            "unknown synthetic kind %r; known kinds: %s"
            % (kind, ", ".join(sorted(GENERATORS)))
        )
    return GENERATORS[kind](rng)


def _simple(kind, build, template):
    """Register a kind whose content is ``template % value``."""
    def fn(rng):
        value = build(rng)
        return template % value, [value]
    generator(kind)(fn)


# --- Personal data -----------------------------------------------------

@generator("personal email")
def _email(rng):
    value = token(rng, 6, LOWER) + "." + token(rng, 7, LOWER) + "@" + token(rng, 9, LOWER) + ".com"
    return "contact: %s\n" % value, [value]


@generator("home path")
def _home_path(rng):
    user = token(rng, 9, LOWER)
    return "see /" + "Users/" + user + "/build/output.log\n", [user]


@generator("Windows home path")
def _windows_home_path(rng):
    user = token(rng, 9, LOWER)
    return "see C:\\" + "Users\\" + user + "\\build\\output.log\n", [user]


@generator("session UUID")
def _session_uuid(rng):
    value = uuid4(rng)
    return "session: %s\n" % value, [value]


@generator("actor id")
def _actor_id(rng):
    value = uuid4(rng)
    return '{"actor' + '_id": "%s"}\n' % value, [value]


# --- Cloud and AI provider credentials ---------------------------------

@generator("AWS key pair")
def _aws(rng):
    access = "AK" + "IA" + token(rng, 16, UPPER_BASE32)
    secret = token(rng, 40, ALNUM + "/+")
    return (
        "aws_access_key_id = %s\naws_secret_access_key = %s\n" % (access, secret),
        [access, secret],
    )


# Provider -> builder. Prefixes are split so no source line is key-shaped.
_PREFIXED = {
    "OpenAI": lambda g: "sk" + "-proj-" + token(g, 156, URLSAFE),
    "OpenAI admin": lambda g: "sk" + "-admin-" + token(g, 156, URLSAFE),
    "Anthropic": lambda g: "sk-" + "ant-api03-" + token(g, 93, URLSAFE) + "AA",
    "Groq": lambda g: "gs" + "k_" + token(g, 52),
    "xAI": lambda g: "xa" + "i-" + token(g, 80),
    "Replicate": lambda g: "r8" + "_" + token(g, 37),
    "Together AI": lambda g: "tgp" + "_v1_" + token(g, 43, URLSAFE),
    "OpenRouter": lambda g: "sk-" + "or-v1-" + token(g, 64, HEX),
    "Fireworks": lambda g: "fw" + "_" + token(g, 24),
    "Cerebras": lambda g: "cs" + "k-" + token(g, 48, LOWER_ALNUM),
    "LangSmith": lambda g: "lsv2" + "_pt_" + token(g, 32, HEX) + "_" + token(g, 10, HEX),
    "ElevenLabs": lambda g: "sk" + "_" + token(g, 48, HEX),
    "Voyage AI": lambda g: "pa" + "-" + token(g, 43, URLSAFE),
    "Pinecone": lambda g: "pcs" + "k_" + token(g, 6) + "_" + token(g, 60),
}

for _provider, _build in _PREFIXED.items():
    _simple(_provider + " key", _build, 'client_credential = "%s"\n')

# Providers whose keys have no fixed prefix are only recognised when assigned
# to a provider-named variable, so the content carries the assignment.
_ASSIGNED = {
    "Mistral": ("MISTRAL_API_KEY", lambda g: token(g, 32)),
    "Cohere": ("COHERE_API_KEY", lambda g: token(g, 40)),
    "Azure OpenAI": ("AZURE_OPENAI_API_KEY", lambda g: token(g, 32, HEX)),
    "Deepgram": ("DEEPGRAM_API_KEY", lambda g: token(g, 40, HEX)),
    "Together AI legacy": ("TOGETHER_API_KEY", lambda g: token(g, 64, HEX)),
}

for _provider, (_variable, _build) in _ASSIGNED.items():
    _simple(_provider + " key", _build, _variable + "=%s\n")


# --- Crypto wallet material --------------------------------------------

@generator("Ethereum private key")
def _eth_key(rng):
    value = "0" + "x" + token(rng, 64, HEX)
    return "signer_key = %s\n" % value, [value]


@generator("Bitcoin WIF key")
def _wif(rng):
    value = wif(rng)
    return "wallet_import = %s\n" % value, [value]


@generator("seed phrase")
def _seed_phrase(rng):
    value = " ".join(rng.choice(WORDS) for _ in range(12))
    return "seed" + "_phrase = %s\n" % value, [value]


# --- Things that must NOT be flagged -----------------------------------

@generator("harmless code")
def _harmless(rng):
    return (
        "def greet(name):\n"
        '    return "hello, " + name\n'
        "\n"
        "print(greet('world'))\n"
    ), []


@generator("public wallet address and digest")
def _public(rng):
    address = "0" + "x" + token(rng, 40, HEX)
    digest = token(rng, 64, HEX)
    return "deposit address: %s\nsha256 digest: %s\n" % (address, digest), []
