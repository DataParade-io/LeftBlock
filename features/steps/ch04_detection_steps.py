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


# --- AWS account and resource identifiers ---------------------------------------
# Each value is assembled at run time from random characters, so no line here
# is shaped like an account id or a resource host name.

DIGITS = "0123456789"
REGION = "us-" + "east-1"


def account_id(rng):
    """A random 12-digit account number that is none of the documented examples."""
    return "7" + token(rng, 11, DIGITS)


@generator("AWS account id in an ARN")
def _arn_account(rng):
    value = account_id(rng)
    return "role = arn:aws:iam::%s:role/deploy\n" % value, [value]


@generator("AWS account id in an ECR host")
def _ecr_account(rng):
    value = account_id(rng)
    return "image: %s.dkr.ecr.%s.amazonaws.com/app:latest\n" % (value, REGION), [value]


@generator("labelled AWS account id")
def _labelled_account(rng):
    value = account_id(rng)
    return 'account_id = "%s"\n' % value, [value]


@generator("AWS account named in prose")
def _prose_account(rng):
    value = account_id(rng)
    return "We deploy this stack to account %s every night.\n" % value, [value]


@generator("Amplify app host")
def _amplify_host(rng):
    value = "d" + token(rng, 13, "abcdefghijklmnopqrstuvwxyz0123456789")
    return "site: https://main.%s.amplifyapp.com\n" % value, [value]


@generator("labelled Amplify app id")
def _amplify_label(rng):
    value = "d" + token(rng, 13, "abcdefghijklmnopqrstuvwxyz0123456789")
    return 'appId: "%s"\n' % value, [value]


@generator("AppSync API host")
def _appsync_host(rng):
    value = token(rng, 26, "abcdefghijklmnopqrstuvwxyz0123456789")
    return "url: https://%s.appsync-api.%s.amazonaws.com/graphql\n" % (value, REGION), [value]


@generator("API Gateway host")
def _gateway_host(rng):
    value = token(rng, 10, "abcdefghijklmnopqrstuvwxyz0123456789")
    return "base: https://%s.execute-api.%s.amazonaws.com/prod\n" % (value, REGION), [value]


@generator("Cognito user pool id")
def _cognito_pool(rng):
    value = REGION + "_" + token(rng, 9, ALNUM)
    return 'user_pool = "%s"\n' % value, [value]


@generator("CloudFront hostname")
def _cloudfront_host(rng):
    value = "d" + token(rng, 13, "abcdefghijklmnopqrstuvwxyz0123456789")
    return "cdn: https://%s.cloudfront.net/\n" % value, [value]


@generator("labelled CloudFront distribution id")
def _cloudfront_label(rng):
    value = "E" + token(rng, 13, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    return "Invalidated distribution %s today\n" % value, [value]


# Not findings: these generators return no values, and the scenarios expect a
# clean commit.

@generator("bare 12-digit numbers")
def _bare_numbers(rng):
    return "order %s shipped at %s\n" % (account_id(rng), "2026" + token(rng, 8, DIGITS)), []


@generator("documented example account ids")
def _example_accounts(rng):
    return (
        "arn:aws:iam::" + "123456789012" + ":root\n"
        "account " + "111122223333" + "\n"
        "account_id = \"" + "000000000000" + "\"\n"
        + "123456789012" + ".dkr.ecr.us-east-1.amazonaws.com/app\n"
    ), []


@generator("AWS ids written as placeholders")
def _placeholder_ids(rng):
    return (
        "arn:aws:iam::<account-id>:role/deploy\n"
        "arn:aws:iam::${AWS_ACCOUNT_ID}:role/deploy\n"
        "pool = us-east-1_EXAMPLE\n"
        "pool = us-east-1_XXXXXXXXX\n"
        "Amplify app deployments are listed in the console\n"
        "git sha 3f2a9c1e7b4d5a60b1c2d3e4f5a6b7c8d9e0f1a2 and PPY-1f1489\n"
    ), []
