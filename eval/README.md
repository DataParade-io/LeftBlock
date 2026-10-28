# Detection evaluation

Measures how much of a labelled corpus of secrets LeftBlock's detectors find,
with counts and Wilson 95% intervals. This directory is **not packaged** and CI
never runs the evaluation; CI only runs the unit tests (`tests/test_eval_*.py`)
and the Gherkin chapter `features/18_measuring_detection.feature`, which use a
tiny fixture dataset and a stub in place of the model.

## Detectors

All four run the same way: `gitleaks dir` for the first two, LeftBlock's own
`deep.scan` for the third.

| | Detector |
|---|---|
| (a) | stock gitleaks, default config |
| (b) | gitleaks with `leftblock/data/gitleaks.toml` |
| (c) | `leftblock deep-scan` with its defaults (labels, 0.9 threshold, exclusions) |
| (d) | (b) and (c) combined: a line is flagged if either flags it |

## Datasets

* **CredData** ([Samsung/CredData](https://github.com/Samsung/CredData), Apache-2.0),
  pinned to commit `fc9b64be`. 297 repositories, about 11k labelled files, values
  obfuscated to same-shape fakes. `meta/*.csv` labels each line T (credential),
  F (not) or X (undecided).
* **Generated corpus**: about 530 small files built at run time from a seeded RNG,
  one realistic fake credential per file (every provider rule LeftBlock ships plus
  AWS, GitHub, Slack, Google, Stripe, PEM keys, JWTs, database URLs and password
  assignments) in `.py .ts .env` YAML, JSON, Markdown, `.ipynb` and shell, plus
  hard negatives (placeholders, UUIDs, hashes, documented example values,
  environment-variable references). Nothing generated is committed or kept.

## Scoring

* **Unit:** a labelled line (a multi-line label such as a PEM key is one unit).
  T and F are scored; X is excluded and counted. If rows disagree about a line, T
  beats F beats X.
* **Hit:** a detector hits a unit when a finding overlaps one of its lines.
* **Metrics:** recall = TP/(TP+FN), precision = TP/(TP+FP), Wilson 95% intervals,
  overall, per category (a unit counts under each of its categories) and for the
  critical tier.
* Precision is precision **on labelled lines**: CredData's F lines are credential-looking
  candidates, so this is a hard-negative precision, not a false-alarm rate.
* Gitleaks also runs on the full files; findings on lines CredData did not label are
  reported as a separate count and never as false positives, because an unlabelled
  line is unreviewed, not known-clean.

## The critical tier

`eval/tiers.py` holds the explicit category mapping. A line is in the tier when any
of its categories is listed:

* `cloud_keys`: AWS Client ID / Multi, Azure Access Token, Google API Key / Multi /
  OAuth tokens, Alibaba
* `private_keys`: PEM Private Key, BASE64 (encoded PEM) Private Key, JWK
* `provider_tokens`: Slack, Twilio, Stripe, MailGun, Perplexity, Anthropic, GitHub,
  Grafana, Dropbox, Salesforce, Akamai, PostHog, Postman, Jira / Confluence PAT,
  Facebook, WunderGraph, Docker Swarm
* `passwords`: Password, SQL / CMD / CMD Secret / CMD Token / ConvertTo-SecureString,
  URL Credentials, CURL User Password
* `auth_headers`: Basic / Bearer / NTLM Authorization, JSON Web Token

Generic categories (Key, Token, API, Secret, Auth, Credential) form a separate
"broad" tier in the JSON; UUIDs, nonces, salts, bucket names, app ids and exotic token
formats are outside both. Change the mapping in one place if you disagree.

## The deep scan is sampled

The model runs at about 1 to 2.5 s per KB of text on CPU (1.1 on an idle M1 Max, 2.0 while the machine was busy), so it cannot read CredData's
19 million lines. It reads **±5 lines around labelled lines**, merged per file:

* all critical-tier true lines (a census);
* plus a stratified random sample of every other labelled line, `--deep-sample N`
  lines (default 1000; strata are truth x critical x first category, at least 3 per
  stratum). Each sampled line carries the weight N_stratum/n_stratum, so rates estimate
  the full dataset and the intervals use the Kish effective sample size.

Gitleaks (a) and (b) are run on the same windows (other lines blanked, numbering kept),
so (b), (c) and (d) compare like with like. The default sample is about 4.9 MB of text, 3.3 MB
of it the census: roughly 1.5 to 2.7 hours in one process. The model uses only about two cores,
so run three shards in parallel (`--deep-shard 0/3`, `1/3`, `2/3`, each with the same other
arguments; they only fill the cache), which was about twice as fast, then run once without
`--deep-shard` to score. The run prints its estimate first. The model may have seen
CredData in training (OpenAI's model card reports a CredData split), so read (c) and (d)
on CredData with that in mind; the generated corpus is the cleaner test.

## Running it

```bash
python -m venv /tmp/lb-eval-venv && /tmp/lb-eval-venv/bin/pip install -e '.[deep]'
# gitleaks on PATH (CI pins 8.30.1)

# CredData: pinned clone + download_data.py; ~10 GB of scratch while it runs, ~1 GB kept.
# The data directory must be OUTSIDE any Git repository (the harness refuses otherwise).
python -m eval fetch --data-dir /tmp/lb-eval-data

python -m eval run --dataset creddata,generated --data-dir /tmp/lb-eval-data
python -m eval run --dataset generated --detectors stock,leftblock   # seconds
python -m eval report                                                # re-render the Markdown
```

Disk: the model weights are about 2.8 GB in the Hugging Face cache; `fetch` refuses to
start with under 30 GB free. Time: gitleaks over CredData takes about 3 minutes, the
deep scan about 1.5 hours (progress is checkpointed per file in `<data-dir>/work`, so an
interrupted run resumes). Clean up afterwards: delete the data directory, the venv and
`~/.cache/huggingface/hub/models--openai--privacy-filter`.

The committed 0.6.0 run: gitleaks over all of CredData about 3.5 minutes (twice, full files
and windows), the generated corpus 8 minutes in one process, the CredData deep scan about
80 minutes of wall time across three to four parallel processes (an hour of the model per
process on a busy M1 Max). Several files in the sample match the deep scan's own skip rules
(minified, lock and generated files), so the model reads less than the 4.9 MB planned.

Results land in `eval/results/<leftblock-version>.json` and `.md`: counts, rates and
category names only. No value, no file content and no dataset file path is written.

## Reading a few details correctly

* A line repeated verbatim in a window set is one `deep.scan` finding; the harness flags
  every window line with identical text.
* LeftBlock's ruleset also flags personal data (UUIDs, emails, home paths) on purpose.
  Against credential-only labels these count as false positives; the report lists the
  rules behind them.
* CredData's rewrite of AWS ids: see the report section "How CredData rewrote AWS access key ids".
