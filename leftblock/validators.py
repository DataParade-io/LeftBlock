"""Post-filters that drop gitleaks findings which fail a real format check.

A regex can only say a string looks like a key. For formats with a checksum
the checksum says whether it is one. `check_findings` runs the validator named
for a finding's rule over the matched text and drops findings that fail, so
coincidental hits (random base64 inside a font or image data URI, say) never
reach the ids or the allowlist. It fails closed: if the matched text cannot be
read, the finding is kept.
"""

import hashlib

from leftblock import allow as allowlist

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: i for i, char in enumerate(BASE58)}
WIF_VERSIONS = (0x80, 0xEF)  # mainnet, testnet


def base58check_decode(text):
    """Payload bytes (version byte included, checksum removed), or None if invalid."""
    if not text or any(c not in _BASE58_INDEX for c in text):
        return None
    number = 0
    for char in text:
        number = number * 58 + _BASE58_INDEX[char]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def valid_wif(text):
    """True for a base58check Bitcoin WIF: version 0x80/0xEF, 32-byte key, optional 0x01."""
    payload = base58check_decode(text)
    if payload is None or payload[0] not in WIF_VERSIONS:
        return False
    return len(payload) == 33 or (len(payload) == 34 and payload[33] == 0x01)


# Rule id -> validator over the matched text. Add a rule here to give it a
# checksum. (The shipped ruleset has no other base58check rule: extended keys
# such as xprv are not in it.)
VALIDATORS = {"leftblock-wif-key": valid_wif}


def check_findings(repo_root, results):
    """Drop findings whose matched text fails the validator for their rule.

    Must run before `allow.attach_ids`, which removes the line and column
    fields this reads. A result left with no findings becomes clean.
    """
    staged = allowlist.StagedFiles(repo_root)
    for result in results:
        if result.error or result.clean or not isinstance(result.findings, list):
            continue
        kept = []
        for finding in result.findings:
            validate = VALIDATORS.get(finding.get("RuleID"))
            texts = staged.match_candidates(finding) if validate else []
            # A wrong column offset yields junk that fails the checksum, so drop
            # only when no candidate reading of the match passes.
            if validate and texts and not any(validate(t) for t in texts):
                continue
            kept.append(finding)
        if kept:
            result.findings = kept
        else:
            result.clean, result.findings = True, None


def passes(rule_id, text):
    """True unless the rule has a validator and the matched text fails it.

    Fails closed: text that could not be read is kept.
    """
    validate = VALIDATORS.get(rule_id)
    return validate is None or not text or bool(validate(text))
