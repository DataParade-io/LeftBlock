# LeftBlock detection evaluation

How much of the secrets in a labelled corpus does LeftBlock find, and how many
harmless lines does it flag along the way? This directory answers that with counts
and 95% intervals, and anyone who clones the repository can re-run it.

It is **not packaged** (`pip install leftblock` does not include it) and CI never
runs the evaluation itself. CI runs the unit tests (`tests/test_eval_*.py`) and the
Gherkin chapter `features/18_measuring_detection.feature`, which use a tiny fixture
dataset and a stub in place of the model. A manual GitHub Actions workflow
(`.github/workflows/eval.yml`) can run the gitleaks half on a clean runner.

Contents: [questions](#the-questions-it-answers) · [quick start](#quick-start) ·
[prerequisites](#prerequisites) · [datasets](#datasets) · [method](#method) ·
[tiers](#the-critical-and-broad-tiers) · [deep-scan sampling](#the-deep-scan-is-sampled) ·
[caveats](#caveats) · [reading the results](#how-to-read-the-results-file) ·
[reproducing and comparing](#reproducing-and-comparing) · [extending it](#adding-a-detector-or-a-dataset) ·
[data handling](#data-handling-rules)

## The questions it answers

1. **Recall.** Of the lines that really are credentials, what share does each detector flag?
2. **Precision.** Of the labelled lines a detector flags, what share are really credentials?
3. **What matters most.** The same two numbers for a *critical tier* of credentials
   (passwords, cloud and provider keys, private keys, auth headers), because missing a
   generic "key" in a config file is not the same as missing a private key.
4. **What each layer adds.** Does LeftBlock's ruleset find more than stock gitleaks? Does
   the model-based deep scan find more than the ruleset, and at what cost in false positives?

It compares four detectors, all run the same way:

| | Detector |
|---|---|
| (a) | stock gitleaks, default config |
| (b) | gitleaks with LeftBlock's shipped ruleset (`leftblock/data/gitleaks.toml`) |
| (c) | `leftblock deep-scan` with its defaults (labels, 0.9 threshold, exclusions) |
| (d) | (b) and (c) combined: a line is flagged if either flags it |

(a) and (b) run through `gitleaks dir`. (c) runs LeftBlock's own `deep.scan`, the code
the real command uses, with the OpenAI Privacy Filter model on CPU.

## Quick start

Everything is one command, run **from the repository root** (`eval/` is not an installed
package). Python 3.10 or newer is recommended (3.8 works for the gitleaks-only run).

```bash
git clone https://github.com/DataParade-io/LeftBlock.git && cd LeftBlock
python3 -m venv .venv-eval && . .venv-eval/bin/activate
pip install -e . -r eval/requirements.txt     # gitleaks-only runs need just: pip install -e . pybase62==1.0.0
# install the pinned gitleaks (next section), then:
python -m eval check --skip-deep              # optional: lists anything missing and how to fix it
python -m eval reproduce --skip-deep
```

| Run | What it does | Time | Disk |
|---|---|---|---|
| `python -m eval reproduce --skip-deep` | gitleaks (a) and (b) on all of CredData and on the generated corpus | CredData download 10 to 20 minutes (once), then about 10 minutes | ~15 GB while downloading, ~3 GB kept |
| `python -m eval reproduce` | adds the deep scan (c) and (d) on the default sample | the above plus 1.5 to 3 hours (CPU) | plus ~2.8 GB for the model weights |
| `python -m eval reproduce --deep-shards 3` | the same, with 3 parallel model processes | about half the deep-scan time | same |
| `python -m eval reproduce --deep-smoke-files 40` | deep scan on 40 files only, to check the pipeline | about 5 minutes more | same |

`reproduce` does, in order: check the prerequisites (and stop with the fix for each one
missing), fetch CredData into the data directory, run the detectors, and write the results
to `<data-dir>/results/<version>.json` and `.md`. The data directory defaults to
`~/.cache/leftblock-eval`; pass `--data-dir` to put it elsewhere, but it must be outside
any Git repository.

**It is resumable.** If it is interrupted (or you press Ctrl-C), run the same command again:
a finished dataset is reused, and the deep scan keeps a per-file checkpoint, so the model
never re-reads a file it finished. `--fresh` throws the checkpoints away. A CredData
download that did not finish is detected and reported rather than used.

When it finishes it prints the command that compares your results with the committed ones:

```bash
python -m eval compare eval/results/0.6.0.json ~/.cache/leftblock-eval/results/0.6.0.json
```

`compare` shows the headline numbers, every differing value, and every input (version, pin,
digest) that differs, side by side. It is informational and always exits 0. With the same
pinned inputs, the gitleaks numbers should match the committed file; deep-scan numbers can
move a little (see [caveats](#caveats)).

Clean up when you are done: delete the data directory and the virtual environment. If you
ran the deep scan, also delete the model (about 2.8 GB). Recent Hugging Face caches store
the weights as a blob under `~/.cache/huggingface/hub/blobs/<xx>/` that the model directory
only links to, so removing the model directory alone leaves the big file behind. This
removes both, touching only blobs that belong to this model:

```bash
python - <<'EOF'
import glob, os, shutil
model = os.path.expanduser("~/.cache/huggingface/hub/models--openai--privacy-filter")
for link in glob.glob(os.path.join(model, "blobs", "*")):
    if os.path.islink(link):
        blob = os.path.realpath(link)
        refs = blob + ".refs"
        if os.path.exists(refs) and "privacy-filter" not in open(refs).read():
            continue  # shared with another model: leave it
        for path in (blob, refs, blob + ".lock"):
            if os.path.exists(path):
                os.remove(path)
shutil.rmtree(model, ignore_errors=True)
EOF
```

## Prerequisites

`python -m eval check` (also run first by `reproduce`) tests all of these and prints the
fix for each one that is missing:

| Need | Why | Fix |
|---|---|---|
| gitleaks **8.30.1** on `PATH` | the pinned version; counts from another version are not comparable. The harness refuses to run otherwise (`--allow-gitleaks-mismatch` runs with a loud warning and records the mismatch in the results) | below |
| git | CredData is cloned at a pinned commit | your package manager |
| Python packages | `pybase62` for CredData's own `download_data.py`; for the deep scan `torch`, `transformers` and friends | `pip install -e . -r eval/requirements.txt` (exact pins) |
| ~25 GB free where the data goes | the download peaks at about 15 GB | free space or `--data-dir` elsewhere |
| ~6 GB more for the deep scan | model weights (2.8 GB) and the download copy | free space |
| network | GitHub (CredData and the repositories it clones), Hugging Face (model) | |

**Installing the pinned gitleaks.** `brew install gitleaks` installs the *latest* release,
which may not be the pinned one, so download the pinned release instead. No `sudo` needed:

```bash
# macOS (Apple silicon: arm64; Intel: x64) or Linux (x64 or arm64)
V=8.30.1; OS=darwin; ARCH=arm64          # OS=linux and ARCH=x64 on a typical Linux box
mkdir -p ~/.local/bin
curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v$V/gitleaks_${V}_${OS}_${ARCH}.tar.gz" | tar -xz -C ~/.local/bin gitleaks
export PATH="$HOME/.local/bin:$PATH"
gitleaks version                         # 8.30.1
```

`python -m eval check` prints this command filled in for your platform. The release page
also lists a checksums file if you want to verify the download.

**Deep scan on Linux.** The default `torch` wheel pulls about 2 GB of CUDA libraries the
CPU-only scan never uses; add `--extra-index-url https://download.pytorch.org/whl/cpu` to
the `pip install` for the small CPU build.

**Versions this was tested with.** Python 3.12 (macOS arm64) and 3.11 (Linux, CI);
the exact package pins are in [`requirements.txt`](requirements.txt) and every results file
records the versions that produced it.

## Datasets

### Samsung CredData

[CredData](https://github.com/Samsung/CredData) is a public benchmark for credential
detectors. Samsung selected 297 open-source GitHub repositories, found candidate lines with
credential scanners and heuristics, and had people label each candidate line. The labelled
rows (`meta/*.csv`) say, per file and line range:

* **T**: this line contains a real credential (and a category: `Password`, `AWS Client ID`,
  `PEM Private Key`, `Slack Token`, `Key`, ...);
* **F**: this line looks like a credential but is not (a placeholder, a hash, a test value);
* **X**: the labellers could not decide.

At the pinned commit that is 11,030 files and 60,820 labelled lines we score (15,280 T,
45,540 F), plus 3,977 X lines we exclude and count.

**Obfuscation.** CredData does not ship the files. Its `download_data.py` re-downloads the
repositories at fixed commits and rewrites every credential value to a random same-shape
fake, so the benchmark contains no live secret. The file layout, surrounding code and
labels are unchanged. This matters for one finding the report documents: the rewrite keeps an
AWS key id's prefix but replaces the rest with random letters and digits, which usually
breaks the base32 alphabet the gitleaks AWS rule needs. Only 102 of the 295 "AWS Client ID"
true lines still look like an access key to gitleaks, and the report scores that subset
separately (100% for both gitleaks configurations). So the headline misses on AWS overstate
real-world misses. It does not use the documented `...EXAMPLE` values gitleaks allowlists
(0 of the labelled rows do), so no category is discounted for that.

**Licences.** CredData's own code and labels are Apache-2.0. The downloaded source files keep
their original repositories' licences. The harness never redistributes any of them: the data
lives only in your data directory, and results carry counts only.

**Pinning.** The harness fetches commit `fc9b64bed812fe2a10b83eaa4498a4ba8f3de5e4`. CredData's
own `snapshot.json` pins each upstream repository, so the commit pins the data too. The
results record that commit and SHA-256 digests of the labels and of the downloaded files, so
you can tell whether your download is byte-identical to the one behind the committed numbers.
(An upstream repository that disappears would change the digest and the file count; the
results record how many labelled rows had no file.)

### The generated corpus

CredData has no modern AI-provider keys, so a second dataset is built at run time from a
seeded random generator (`eval/generated.py`, default seed 20261028): 528 small files, one
planted fake credential (or an AWS key pair) per file, in eight file types (`.py .ts .env`
YAML JSON Markdown `.ipynb` shell). It covers every provider rule LeftBlock ships plus AWS,
GitHub, Slack, Google, Stripe, PEM keys, JWTs, database URLs and password assignments. Each
planted credential comes in two flavours:

* **named**: the variable is named for the provider (`OPENAI_API_KEY`), the easy case;
* **bare**: a neutral name (`payload`, `blob`) with none of gitleaks' generic keywords, so
  only the key's own shape can give it away.

**Hard negatives** (label F) sit in the same contexts: placeholders (`sk-xxxx`), UUIDs,
hashes, documented example values and environment-variable references
(`os.environ["OPENAI_API_KEY"]`). These are the lines a careless detector flags.

The values are assembled at run time (key prefixes are split in the source so nothing in the
repository is key-shaped), written under the data directory, scanned and deleted. Nothing
generated is committed. The corpus's SHA-256 is recorded in the results.

It is a test of *known formats*, and the same authors wrote the rules and the corpus, so
read it as "does each rule fire on the format it was written for", not as an independent
estimate. For the deep scan it is the cleaner test, because the model cannot have seen it.

### Why there is no git-history dataset

LeftBlock gates *commits*, but no public labelled dataset of secrets in git history exists
(CredData is labelled snapshots of files, not diffs). Building one would mean planting our
own secrets, which is what the generated corpus already does. So the evaluation measures
what a detector finds in *file content*; how the gate reads a diff is covered by the
Gherkin specs instead.

## Method

**The unit is a labelled line range.** One CredData label is a file, a first and a last
line, a truth (T/F/X) and categories. A multi-line label (a PEM key) is one unit. If several
rows label the same range they are merged: T beats F beats X, and the categories of every
row with the winning truth are kept (so a line labelled both Password and Username counts
under both).

**A detector hits a unit** when any of its findings overlaps any line of the unit. Each
detector reduces to the set of `(file, line)` pairs it flagged; nothing else about a finding
is kept.

* TP: a T unit that is hit. FN: a T unit that is not.
* FP: an F unit that is hit. TN: an F unit that is not.
* Recall = TP / (TP + FN). Precision = TP / (TP + FP).
* Every rate comes with a **Wilson 95% interval** (`eval/stats.py`).

**X is excluded.** Lines the labellers could not decide are neither credentials nor
non-credentials, so they are left out of every rate and counted (3,977 lines).

**Precision on labelled lines is not a false-alarm rate.** CredData's F lines are
*candidates*: lines a scanner or heuristic thought looked like credentials, which a person
then rejected. They are hard negatives. A detector's precision here is far lower than on
arbitrary code and says nothing about the other 19 million unlabelled lines. Use it to
compare detectors, not to predict how noisy LeftBlock is in your repository.

**Flags on unlabelled lines are reported apart.** Gitleaks scans whole files, so it also
flags lines CredData has no label for. These are not counted as false positives: an
unlabelled line is unreviewed rather than known clean, and some may be real credentials the
labelling missed. The report shows their number only to size the unreviewed noise.

**LeftBlock's personal-data rules count as false positives here.** LeftBlock's ruleset also
flags UUIDs, email addresses and home-folder paths on purpose (it is a privacy gate, not
only a secret scanner). Against credential-only labels, those flags land on F lines and
count against precision. The report names the rules behind the false positives so you can
see how much of (b)'s precision gap is `leftblock-session-uuid` and `leftblock-personal-email`
rather than credential rules.

**A repeated line is one deep-scan finding.** `deep.scan` reports one finding per distinct
(rule, file, line text); the harness credits every window line with identical text.

## The critical and broad tiers

`eval/tiers.py` holds an explicit mapping from category names to groups; a line is in the
tier when **any** of its categories is listed. Nothing is inferred.

**Critical tier** (the headline) is the union of five groups:

| Group | CredData categories |
|---|---|
| `cloud_keys` | AWS Client ID, AWS Multi, Azure Access Token, Google API Key, Google Multi, Google OAuth Access Token, Google OAuth Refresh Token, Alibaba Access Key ID, Alibaba Multi |
| `private_keys` | PEM Private Key, BASE64 Private Key, BASE64 encoded PEM Private Key, JWK |
| `provider_tokens` | Slack Token, Twilio Credentials, Twilio Multi, Stripe Credentials, MailGun API Key, Perplexity API Key, Anthropic API Key, Github Classic Token, Grafana (three kinds), Dropbox App secret, Salesforce Credentials, Akamai Credentials, PostHog Credentials, Postman Credentials, Jira / Confluence PAT token, Facebook Access Token, WunderGraph API Key, Docker Swarm Token |
| `passwords` | Password, SQL Password, CMD Password, CMD Secret, CMD Token, CMD ConvertTo-SecureString, URL Credentials, CURL User Password |
| `auth_headers` | Basic Authorization, Bearer Authorization, NTLM Token, JSON Web Token |

(The generated corpus's category names, such as `OpenAI key` or `Database URL password`,
are mapped into the same groups.)

**Broad tier** = critical plus the **generic** categories `Key`, `Token`, `API`, `Secret`,
`Auth`, `Credential`: labels where the annotators could not name a provider, so they mix
real keys with configuration noise. They are in the JSON (`broad`) but not in any headline.

**Outside both:** UUIDs, nonces, salts, bucket names, app ids, activation keys, OTP seeds
and unusual token protocols (NKEY, PASERK, PASETO). They are real but are not
account-takeover credentials in the sense of the question. If you disagree, change the
mapping in `eval/tiers.py`; the results record a digest of the tier definition so a changed
mapping shows up in `compare`.

## The deep scan is sampled

The model costs about 1 to 2.5 seconds per kilobyte of text on CPU, so it cannot read
CredData's 19 million lines. It reads **windows of ±5 lines around labelled lines**, merged
per file, for a sample of units chosen like this (`eval/creddata.py`, `select_sample`):

* **Census of the critical tier.** Every critical-tier true unit (5,884) is included,
  weight 1. The headline question is about these, so none are sampled away.
* **Stratified sample of the rest.** Every other unit is grouped into strata
  (truth × critical-or-not × first category) and a seeded random sample is drawn,
  `--deep-sample N` units in all (default 1,000), at least 3 per stratum (or all of a
  smaller stratum). The default run reads about 4.9 MB of text, 3.3 MB of it the census.
* **Weights.** A unit sampled from a stratum of N_stratum units, n_stratum of which were
  drawn, carries weight N_stratum / n_stratum. Weighted counts estimate the full-dataset
  counts; the TP/FP/FN columns in the sample tables are these **population estimates**.

Gitleaks (a) and (b) are run on the same windows (all other lines blanked, numbering kept),
so (b), (c) and (d) compare like with like in the sample tables.

**Why the intervals widen.** A weighted sample carries less information than its size: a
few units with big weights stand in for many. The interval uses the **Kish effective sample
size**, n_eff = (Σw)² / Σw², instead of the raw count, so the sampling error is inside the
interval. The critical-tier rows use the census (weight 1), which is why their intervals are
narrow while the overall rows in the sample are wider than the full-file gitleaks rows.

**Sharding.** The model uses only a few cores, so `--deep-shards N` runs N processes, each
scanning every N-th file into the checkpoint cache; a final single process scores. Smoke
mode (`--deep-smoke-files N`) restricts the model to N seeded files: the pipeline runs end to
end, but the deep numbers are **not estimates** (the report and the JSON say `SMOKE RUN`).

## Caveats

* **The model may have seen CredData.** OpenAI's Privacy Filter model card reports a CredData
  split, so (c) and (d) on CredData may be optimistic. The generated corpus is the cleaner
  test of the deep scan.
* **Windows are not production.** The deep scan normally reads the added lines of a diff.
  Here it reads ±5 lines around labelled lines: the same text with the same exclusions, but
  labelled lines are over-represented compared with real diffs.
* **Deep-scan numbers can move a little between runs and machines.** CPU inference with
  different thread counts, `torch` builds or hardware can change a score in the last digits,
  which can flip a span that sits right at the 0.9 threshold. The weights are pinned
  to a Hugging Face commit, but the harness does not claim bit-exact deep-scan results; the
  gitleaks numbers depend only on the pinned inputs.
* **The deep scan skips some files by design** (minified, lock and generated files), so the
  model reads less than the 4.9 MB planned.
* **Critical-tier choices are judgment calls** (see above).
* **The generated corpus is self-authored** (see above).
* **One snapshot.** CredData is a snapshot of files, not a stream of commits.

## How to read the results file

`python -m eval reproduce` writes two files with the same content: `<version>.json` (all
the numbers) and `<version>.md` (the same, rendered). The committed ones are
[`results/0.6.0.json`](results/0.6.0.json) and [`results/0.6.0.md`](results/0.6.0.md).
They contain counts, rates and category names only.

**Top level of the JSON**

```
leftblock_version, gitleaks_version
provenance            what produced this file (next section)
datasets
  creddata
    pin, seed, deep_sample_requested
    inputs            CredData commit and SHA-256 digests of what was read
    units             how many labelled lines, files, X exclusions, ...
    probes            the AWS-key obfuscation counts
    full_files        gitleaks (a)(b) on every labelled line
    windows           all four detectors on the deep-scan sample
    unlabelled_flags  findings on lines nobody labelled
  generated           the same shape, plus "tags" (by context, flavour, negative kind)
```

`full_files` and `windows` hold `detectors.<name>.{overall, critical, broad, groups,
categories, rules}` and `adds` (what a layer finds that the one below it does not). Each
metric block has `counts` (raw tp/fp/fn/tn), `estimated` (weighted, equal to counts when
there is no sampling), and `recall` and `precision` as `{value, lo, hi, n}`.

**Worked example: the 0.6.0 headline.** The first table in `0.6.0.md` is this row for
(b) gitleaks with LeftBlock's ruleset, on the full dataset:

| Detector | Recall (95% CI) | Precision (95% CI) | TP / FP / FN | Critical recall |
|---|---|---|---|---|
| (b) | 60.2% (59.5-61.0) | 75.0% (74.2-75.8) | 9203 / 3067 / 6077 | 31.6% (30.4-32.8) |

* `datasets.creddata.full_files.detectors["gitleaks-leftblock"].overall.counts` is
  `{tp: 9203, fp: 3067, fn: 6077, tn: 42473}`. The T units are 9203 + 6077 = **15,280**, the
  F units 3067 + 42473 = **45,540** (these match `units.true` and `units.false`).
* Recall = 9203 / 15,280 = **60.2%**. Of 15,280 lines labelled as credentials, (b) flagged
  60.2%. The interval is 59.5 to 61.0%: with this many lines the sampling error is small.
* Precision = 9203 / (9203 + 3067) = **75.0%**. Of the 12,270 labelled lines (b) flagged,
  three quarters are credentials. Remember that the F lines are candidates, and that 1,712 of
  the 3,067 false positives are `leftblock-session-uuid` flags (see
  `…overall` → `rules.false_positive_units`), a rule credential labels cannot reward.
* **Critical recall is 31.6%**, not 60.2%. The critical tier has 5,884 true lines and (b)
  hit 1,857 (`…critical.counts`). The difference from the overall number is mostly
  `passwords` (3,037 true lines, 8.5% recall): most CredData passwords are assignments with
  innocuous values that only a model reads as secrets. That gap is what motivates the deep
  scan, and the sample table shows it (c) at 83.8% critical recall.
* In the **sample table** the same row reads 57.7% recall and 8,818 / 3,051 / 6,462: those
  TP/FP/FN are *population estimates* from weighted sampled lines, which is why the interval
  (53.1 to 62.1%) is wider than the full-file one although the point estimate agrees.
* "TP / FP / FN" in the Markdown is raw counts for full files and estimates for the sample.

**Provenance** (`provenance` in the JSON, "Provenance" in the Markdown) records everything
that can change the numbers, so a difference can be explained:

| Field | Meaning |
|---|---|
| `leftblock` | version, git SHA of the checkout, whether it had uncommitted changes |
| `gitleaks` | version found, version pinned, `matches_pin` |
| `eval.ruleset_sha256`, `eval.tiers_sha256` | digests of LeftBlock's shipped ruleset and of the tier mapping |
| `arguments` | seed, deep sample size, smoke-run file count, detectors and datasets run |
| `deep_scan` | model, **Hugging Face revision**, labels, threshold, torch threads (null when no deep scan ran) |
| `environment` | Python and OS, and versions of `torch`, `transformers`, ... |
| `datasets.creddata.inputs` | CredData commit, SHA-256 of the labels and of the files, file count |
| `datasets.generated.inputs` | seed and SHA-256 of the generated corpus |

## Reproducing and comparing

`python -m eval reproduce` is the supported way to produce a results file. To check that
you reproduced the committed numbers, run `python -m eval compare` (printed at the end of
`reproduce`) and read it as follows:

1. **"Inputs and environment that differ".** If a pin or digest differs (gitleaks version,
   CredData digest, ruleset digest), the numbers are not expected to match; fix that first.
   Differences in Python, OS or package versions are normal.
2. **"Values that differ".** With identical inputs the gitleaks values (`full_files`, the
   generated corpus's (a) and (b)) match exactly. Deep-scan values (`windows`, and (c)/(d) on
   the generated corpus) may differ slightly, as explained in the caveats.

Details worth knowing:

* `reproduce` writes to `<data-dir>/results`, never over `eval/results/`. To update the
  committed results on purpose: `python -m eval reproduce --results-dir eval/results`.
* Without the deep scan, `compare` simply has no `windows` section to compare and says so.
* The lower-level `python -m eval run` runs chosen detectors on chosen datasets and merges
  into an existing results file; `python -m eval report` re-renders the Markdown from the
  JSON; `python -m eval fetch` only downloads the data.

**GitHub Actions.** `.github/workflows/eval.yml` is run by hand (Actions tab, "Eval",
"Run workflow"). It reproduces the gitleaks half on a clean Linux runner, prints the
`compare` output in the job summary and uploads the results as an artifact. Ticking "deep"
adds a smoke deep scan on a few files. It never commits, never fails on a difference, and
does not run on push or pull request.

## Adding a detector or a dataset

**A detector** reduces to a `Flags` object (`eval/detectors.py`): the set of `(file, line)`
pairs it flagged and a count of findings per rule.

1. Write `run_<name>(...)` in `eval/detectors.py` returning `Flags` (look at `run_gitleaks`).
2. Give it a constant next to `STOCK`, `LEFTBLOCK`, `DEEP`, `COMBINED` and add it to `ALL`.
3. Add it to `ALIASES` in `eval/__main__.py` (the `--detectors` names), to `NAMES` and
   `ORDER` in `eval/report.py`, and call it from `run_creddata` and `run_generated` in
   `eval/runner.py`. Scoring needs nothing else: `scoring.hit_units` and `evaluate` handle
   any detector.
4. Add a Gherkin scenario to `features/18_measuring_detection.feature` and, if it needs a
   stub, extend `features/stub_detector.py`. Pin anything external in `eval/pins.py`.

**A dataset** reduces to labelled units (`scoring.make_unit(file, start, end, truth,
categories)`) plus a directory the detectors can scan.

1. Write a loader in a new module that returns units (T and F only; count X separately).
2. Write `run_<dataset>` in `eval/runner.py` modelled on `run_generated`: build or load the
   units, run the detectors, call `evaluate`, return a record with an `inputs` block of pins
   and digests.
3. Add the name to `DATASETS` in `eval/__main__.py` and a section to `eval/report.py`.
4. Map any new category names into `eval/tiers.py`, and keep the data outside the repository
   (below).

## Data handling rules

* **The data stays outside the repository.** The harness refuses a data directory inside any
  Git repository (CredData is credential-shaped text; this gate or a careless `git add .`
  could otherwise see it), and `.gitignore` lists the usual download names as a second guard.
* **Reports carry counts only.** A results file holds counts, rates, category names, rule
  ids and digests. Never a secret value, a line of a file, or a dataset file path. Specs
  check this (`features/18_measuring_detection.feature`).
* **Nothing generated is kept.** The generated corpus is deleted after each run.
* **No credentials needed.** The evaluation downloads public data and a public model; it
  never asks for a token.
