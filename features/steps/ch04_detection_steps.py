"""Chapter 4 (what LeftBlock detects): extra synthetic kinds and one step.

Every value is assembled at run time, so no line here is shaped like a secret,
an address or a home path.
"""

from behave import given

import world
from synthetic_data import (
    ALNUM, BASE58, HEX, URLSAFE, WORDS, bad_checksum, generator, token, wif,
)


# --- Personal data ---------------------------------------------------------

@given('a staged file "{name}" containing an address "{local}" at "{domain}"')
def step_staged_address(context, name, local, domain):
    """Stage ``contact: <local>@<domain>``; the address is remembered as a
    value no output may reveal. The two halves are separate in the feature
    file so the file itself holds no address."""
    address = local + "@" + domain
    context.synthetic_values.append(address)
    world.write_file(context, name, "contact: %s\n" % address)
    world.git(context, "add", name)


@generator("Linux home path")
def _linux_home_path(rng):
    user = token(rng, 9, "abcdefghijklmnopqrstuvwxyz")
    return "see /" + "home/" + user + "/build.log\n", [user]


# --- Cloud and wallet material ----------------------------------------------

@generator("Google API key")
def _google_key(rng):
    value = "AI" + "za" + token(rng, 35, URLSAFE)
    return "GEMINI_API_KEY=%s\n" % value, [value]


@generator("uncompressed WIF key")
def _uncompressed_wif(rng):
    value = wif(rng, compressed=False)
    return "wallet_import = %s\n" % value, [value]


@generator("WIF-shaped string with a bad checksum")
def _bad_wif(rng):
    return "wallet_import = %s\n" % bad_checksum(wif(rng)), []


@generator("minified stylesheet with a font data URI holding a WIF-shaped run")
def _font_data_uri(rng):
    run = bad_checksum(wif(rng))
    base64 = token(rng, 60, ALNUM)
    css = (
        "@font-face{font-family:x;src:url(data:font/woff2;base64,%s/%s+%s) format(woff2)}"
        ".card{padding:1rem}\n" % (base64, run, token(rng, 60, ALNUM))
    )
    return css, []


@generator("labelled bare hex private key")
def _bare_hex_key(rng):
    value = token(rng, 64, HEX)
    return "private" + "_key = %s\n" % value, [value]


@generator("labelled bare and 0x-prefixed hex private keys")
def _bare_and_prefixed_keys(rng):
    bare, prefixed = token(rng, 64, HEX), "0" + "x" + token(rng, 64, HEX)
    return (
        "private" + "_key = %s\neth_private" % bare + "_key = %s\n" % prefixed,
        [bare, prefixed],
    )


def _phrase(rng, words):
    return " ".join(rng.choice(WORDS) for _ in range(words))


def _phrase_kind(kind, template, words):
    def build(rng):
        value = _phrase(rng, words)
        return template % value, [value]
    generator(kind)(build)


for _count in (12, 15, 18, 21, 24):
    _phrase_kind("%d-word seed phrase" % _count, "seed phrase: %s\n", _count)

_phrase_kind("quoted seed phrase assignment", 'seed' + '_phrase = "%s"\n', 12)
_phrase_kind("tightly quoted seed phrase assignment", 'seed' + '_phrase="%s"\n', 12)
_phrase_kind("colon mnemonic line", "mnemonic: %s\n", 15)
_phrase_kind("quoted vault seed assignment", 'vault' + '_seed = "%s"\n', 24)


# --- Look-alikes that must not be flagged ------------------------------------

@generator("Bitcoin address and git and SHA-512 digests")
def _public_digests(rng):
    return (
        "btc address: 1" + token(rng, 33, BASE58) + "\n"
        "commit " + token(rng, 40, HEX) + "\n"
        "sha512: " + token(rng, 128, HEX) + "\n"
    ), []


@generator("unlabelled hex blob")
def _hex_blob(rng):
    return token(rng, 64, HEX) + "\n", []
