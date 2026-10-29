# CHANGELOG

These are release summaries. LeftBlock 0.3.2 was the first release of the
current `leftblock` package on PyPI; earlier release numbers refer to the
earlier distribution. Summaries use
current terminology where helpful. Original commits, receipts, and releases
remain unchanged; commit links retain their original hashes.

<!-- version list -->

## v0.8.0 (2026-10-29)

### Documentation

- Diagram shows recorded overrides and the optional deep scan; drop donation wording; compare skips
  smoke samples
  ([`eb5b0b0`](https://github.com/DataParade-io/LeftBlock/commit/eb5b0b01cbd5d2646e5c7de3c064440db6fc7273))

- Name the OpenAI Privacy Filter model in the intro, diagram and results
  ([`c2af290`](https://github.com/DataParade-io/LeftBlock/commit/c2af2906cd9a4ce43bdf28380367263bac042faf))

- **eval**: Cleanup of the Hugging Face cache and step vocabulary
  ([`b636143`](https://github.com/DataParade-io/LeftBlock/commit/b6361436a5bd38cbdcd8573e3e2b996e628504de))

- **eval**: Measured sizes and times, venv ignore, runner disk step
  ([`ad1b2bd`](https://github.com/DataParade-io/LeftBlock/commit/ad1b2bda067a4ac82bd853fb2ec19faac316adfe))

### Features

- **eval**: Reproduce, check and compare commands, pinned inputs and recorded provenance
  ([`48ef6e6`](https://github.com/DataParade-io/LeftBlock/commit/48ef6e63f3606d1ff2e5b875cb05fb5a5acf1453))


## v0.7.0 (2026-10-28)

### Features

- **eval**: Add detection-evaluation harness
  ([`cc770a8`](https://github.com/DataParade-io/LeftBlock/commit/cc770a848550de533299f2e824da1de20cfbc563))

Scores stock gitleaks, gitleaks with the shipped ruleset, the deep scan and their combination
  against labelled lines (CredData and a generated corpus), with Wilson intervals, a critical tier
  of credential categories, X lines excluded and counted, flags on unlabelled lines kept apart, and
  a stratified, weighted sample so the deep scan reads context windows rather than 19M lines. Adds
  unit tests and Gherkin chapter 18.

- **eval**: Shard the deep scan and add the 0.6.0 results
  ([`3f40768`](https://github.com/DataParade-io/LeftBlock/commit/3f407682f6dee434e63e238b8e4775f281a10162))

The model uses only about two cores, so --deep-shard K/N lets several processes fill the per-file
  cache in parallel before a final run scores it. Adds the first committed run: CredData (60,820
  labelled lines, deep scan on a 6,979-line weighted sample) and the generated corpus (528 files).


## v0.6.0 (2026-10-28)

### Chores

- **kanbus**: File full-repository scan option
  ([`77685a9`](https://github.com/DataParade-io/LeftBlock/commit/77685a979f7c1988c4c11ba1472b3cf7f96715d6))

- **kanbus**: Status update before pause; close items with evidence
  ([`e0a682a`](https://github.com/DataParade-io/LeftBlock/commit/e0a682a54bc4e38b3cc3024af9642a1207cacfca))

- **kanbus**: Story for OpenAI Privacy Filter integration
  ([`3a281fe`](https://github.com/DataParade-io/LeftBlock/commit/3a281fe7bb0f755cd67fd5ee25350821093fbee9))

### Features

- **deep-scan**: Add opt-in model-based deep scan
  ([`d92ca11`](https://github.com/DataParade-io/LeftBlock/commit/d92ca11114dd5ed792b2a90025b7d8d90d609908))

leftblock deep-scan reads the added lines of the staged diff (or of a commit range with --range
  A..B, for CI) with OpenAI's Privacy Filter through the transformers token-classification pipeline
  on CPU. It ships as the optional leftblock[deep] extra and is never run by the commit hook.

Defaults come from a local evaluation: secret, private_email, private_phone and private_address at
  score >= 0.9; the other four labels are opt-in with --labels, the cut-off is --threshold. Kanbus
  board data, generated/vendored/lock files, identifier-shaped secrets, placeholder lines and
  already-allowed addresses are skipped. Findings carry recorded override ids (rule
  privacy-filter-<label>, leftblock allow --deep) and never print the matched value.

The detector sits behind a text -> (start, end, label, score) interface; specs swap it for a stub
  via LEFTBLOCK_DEEP_DETECTOR. Adds chapter 17 specs and unit tests for the filters.


## v0.5.1 (2026-10-22)

### Bug Fixes

- A broken or missing policy is explained in plain words by the commit hook instead of a stack trace
  ([`2457ae2`](https://github.com/DataParade-io/LeftBlock/commit/2457ae2d8c7a4827fcc8e8b8a1056e176ffbf61c))

leftblock hook now prints the same configuration error as check and blocks the commit.

- A merge with unresolved conflicts is reported plainly instead of crashing
  ([`58c75c0`](https://github.com/DataParade-io/LeftBlock/commit/58c75c09384da8434dda53521b399769bf9837d5))

leftblock check and the hook now say the index has unresolved conflicts and to resolve them first;
  check exits 2.

- A refused install no longer leaves a hook behind when the runtime location is not a symlink
  ([`9170e55`](https://github.com/DataParade-io/LeftBlock/commit/9170e5536359d45acc2864286f8342be2b8d8de1))

The runtime link is now validated before anything is written, so a refused install changes nothing.

### Continuous Integration

- Run specs without @wip, install setuptools and wheel, fail on any skipped scenario
  ([`c864665`](https://github.com/DataParade-io/LeftBlock/commit/c86466594df25cf091e9edf20b98641d114393d8))

### Testing

- Gherkin spec foundation and narrative index
  ([`c55d41a`](https://github.com/DataParade-io/LeftBlock/commit/c55d41a20b2c9943ebf7ddb46d6b80a1120f8466))

- Spec canonical Kanbus event and cache files with Windows line endings
  ([`944c1b9`](https://github.com/DataParade-io/LeftBlock/commit/944c1b951cf94e788743cdd6a76c800b027935ea))

- Specs for detection rules, Kanbus board data and reading a block
  ([`28814fc`](https://github.com/DataParade-io/LeftBlock/commit/28814fcde09897cdb76c81ad247f399276a15ce1))

- Specs for dry runs, machine output, recorded overrides and silent bypasses
  ([`0be5db1`](https://github.com/DataParade-io/LeftBlock/commit/0be5db1beb75ea0ea1b723afaffe06d197b19de9))

- Specs for failing closed, merge commits, receipts and custom checkers
  ([`21fc6eb`](https://github.com/DataParade-io/LeftBlock/commit/21fc6ebe4bb1cc3f02f08823e276c55b479b0cde))

- Specs for installation, runtime upgrades and the command line
  ([`43424f8`](https://github.com/DataParade-io/LeftBlock/commit/43424f82c9e01c79c87db80ad32496c6966379c3))


## v0.5.0 (2026-10-22)

### Features

- Detect API keys from common AI providers (Groq, xAI, Together, OpenRouter, Mistral, Cohere, Azure
  OpenAI and more)
  ([`dd80b1e`](https://github.com/DataParade-io/LeftBlock/commit/dd80b1e251c20aceeeb530dd13ba290c84203a62))

### Testing

- Gherkin specs for AI provider key detection
  ([`29de696`](https://github.com/DataParade-io/LeftBlock/commit/29de696b0e76b03e4c8fd08ecaa3c86304befb8a))


## v0.4.3 (2026-10-21)

### Bug Fixes

- Accept RFC-reserved placeholder email domains and name them in the hint
  ([`631b786`](https://github.com/DataParade-io/LeftBlock/commit/631b7865a5af13471c3ec9e971aba1cf4281a17b))

### Chores

- **kanbus**: Track CI-side scan and role-address allowance
  ([`24a5ac3`](https://github.com/DataParade-io/LeftBlock/commit/24a5ac3d01d25719d1a7bec91ddb14729828d312))


## v0.4.2 (2026-10-21)

### Bug Fixes

- Include Kanbus's LLM usage log in board data
  ([`4a85eef`](https://github.com/DataParade-io/LeftBlock/commit/4a85eefc6e7c2e9db155933ebf0d4a27df1b6831))

- Treat Kanbus board identifiers as non-sensitive so kbs writes never block
  ([`619c6a9`](https://github.com/DataParade-io/LeftBlock/commit/619c6a906965e833026d87420ece98c696daff51))

- **ci**: Let a rerun publish a tagged release whose upload failed
  ([`ced9575`](https://github.com/DataParade-io/LeftBlock/commit/ced9575879e754e26a7bca85cd814bb36f8d1ca9))


## v0.4.1 (2026-10-21)

### Bug Fixes

- Give Kanbus event files delete-and-recreate advice; events are append-only
  ([`2d18b8d`](https://github.com/DataParade-io/LeftBlock/commit/2d18b8ddef98e9a2f94147177a68efde1bd66c36))

- Treat no-reply addresses as non-personal and keep commit trailers out of the changelog
  ([`a51cda0`](https://github.com/DataParade-io/LeftBlock/commit/a51cda023ad6ca07d4066beb9c40299bbac31ee0))

### Chores

- **kanbus**: Close usability tasks shipped in 0.4.0
  ([`6064839`](https://github.com/DataParade-io/LeftBlock/commit/6064839d1f6babc68f41495c9b0e283b160b1e82))


## v0.4.0 (2026-10-21)

### Bug Fixes

- Block silent Gitleaks bypasses and record staged overrides as allowed in receipts
  ([`660b8db`](https://github.com/DataParade-io/LeftBlock/commit/660b8db62a6e419d9eb22b68126928b141e199af))

- Scan lines with inline allow comments and warn about a root .gitleaksignore
  ([`465874f`](https://github.com/DataParade-io/LeftBlock/commit/465874f22141e09296d685f476043e9f827bcd74))

### Continuous Integration

- Release with python-semantic-release on every push to main
  ([`5f7dc37`](https://github.com/DataParade-io/LeftBlock/commit/5f7dc373f0abd00ab6a200ca975403573199c103))

Restores semantic-release: versions come from conventional commits, and the workflow tags, updates
  CHANGELOG/README, publishes to PyPI via trusted publishing, creates the GitHub release and merges
  back into develop. Tests read the version from pyproject.toml instead of hard-coding it.

### Features

- Add --version, name the ruleset in blocked output, and make check a documented dry run
  ([`0f68708`](https://github.com/DataParade-io/LeftBlock/commit/0f6870814a97b25e6fcd62e4629c359ba880d4bd))

- Add check --format json and distinct exit codes for blocked and error
  ([`ba85888`](https://github.com/DataParade-io/LeftBlock/commit/ba85888e4c065ce409425aae616a19c11ccafa6d))

- Keep a stable runtime link so upgrades reach every repository's hook
  ([`82b2cd9`](https://github.com/DataParade-io/LeftBlock/commit/82b2cd9b8c1a7f391cb5f00a2c16422902640346))

- Print advice for each rule and point Kanbus board findings at kbs
  ([`7ce1dac`](https://github.com/DataParade-io/LeftBlock/commit/7ce1dace7169b0770ef606a92c2e6e35db2a36a2))

- Print line numbers and rule descriptions for findings
  ([`3f8b1ef`](https://github.com/DataParade-io/LeftBlock/commit/3f8b1ef897a528623d899a87126e49059198c191))


## v0.3.5 (2026-10-20)

### Fix

- Printed override commands are safe to paste. They use `leftblock` when that
  name on PATH runs the same installation (for example a `~/.local/bin/leftblock`
  link to the current runtime). Otherwise they show the interpreter with the
  home directory as `~`, so the advice never trips the home-path rule.
- Finding lines read `file: rule [id ...]` instead of raw JSON.

## v0.3.4 (2026-10-20)

### Feature

- Recorded per-finding overrides. A blocked `leftblock check` now prints an
  id for each finding and the `leftblock allow ID --reason TEXT` command,
  which records a scoped entry in a committed `.leftblock-allow.yml` and
  stages it. An entry covers one rule on one exact line content in one file,
  needs a reason of at least 10 characters, and counts only when staged.
  Applied overrides are printed on every run; invalid allow files and scanner
  errors still block.
- The final blocked line now names each rule, file and finding id and the
  next step, so tools that show only the last line (such as `kbs commit`)
  still explain the block.
- Output has no colour codes when it is captured or `NO_COLOR` is set.

## v0.3.3 (2026-10-20)

### Fix

- Allow the public Kanbus `project_id` (a UUID v4) as a top-level key in
  `.kanbus.yml`. Other keys, indented keys and other files stay detected.

## v0.2.0 (2026-10-03)

### Chore

* chore: add Kanbus board for the out-of-the-box detection initiative

Initiative kanbus-f66623 with epics for scanner evaluation, shipped
detection rules, the deterministic test suite, hook dogfood, scan
records and the PR gate. Work items carry agent provenance using synthetic
identities. ([`d0653d4`](https://github.com/DataParade-io/LeftBlock/commit/d0653d4812d3f4b3c5c537f62114d669641660f4))

### Ci

* ci: run full suite with pinned gitleaks on main and develop; dogfood self-scan

CI installs gitleaks 8.30.1, runs the unit tests and BDD specs, and
scans the LeftBlock tree with its own shipped ruleset. README documents
out-of-the-box detection, the crypto wallet flagging policy (public
addresses and hashes are not flagged by themselves), and the scanner
evaluation matrix. At that release, CI carried a narrow exception for a
contact address copied into the generated changelog; the current summaries
omit that personal metadata. ([`b247cd2`](https://github.com/DataParade-io/LeftBlock/commit/b247cd275e2c400fd65105eeda1c90572c04aa6f))

### Documentation

* docs: document package-index installation for the earlier distribution ([`e4afa8e`](https://github.com/DataParade-io/LeftBlock/commit/e4afa8ec36be23e8b1a456aa0d11d7a74ffede29))

### Feature

* feat: out-of-the-box sensitive-data detection

Ship a gitleaks ruleset (leftblock/data/gitleaks.toml) that extends the
gitleaks defaults with personal-data and crypto-wallet rules: personal
emails, home paths (POSIX and Windows), session UUIDs, actor IDs,
OpenAI/Anthropic API keys, Ethereum-style private keys, WIF Bitcoin
keys, and BIP-39 seed phrases (12-24 words in seed/mnemonic context).

&#39;leftblock install&#39; now writes a default .leftblock.yml pointing at the
shipped ruleset and copies the ruleset into .leftblock/, never
overwriting existing files. The ruleset ships as package data.

Public wallet addresses and hash-like hex (SHA-256/git SHA) are not
flagged on their own; bare 64-hex is only reported in key-like keyword
context. Bytecode caches (__pycache__) are excluded as compiled
artifacts. ([`6e65b55`](https://github.com/DataParade-io/LeftBlock/commit/6e65b55c93952ef4eed751fd83b7f831bbc6b7eb))

### Test

* test: pass the hook environment to git commit in sensitive-data steps

The behave steps set LEFTBLOCK_SECRET_PATH in their own env but did not
forward it to git commit, so the commit-msg hook could not find the
test secret and the allow-clean scenarios failed on machines without
~/.config/leftblock/secret (masked locally by an existing secret file). ([`2e7c385`](https://github.com/DataParade-io/LeftBlock/commit/2e7c385476133b7a1a3959f62c998452dfc0b0ff))

* test: deterministic synthetic-fixture suite for the shipped ruleset

Unit tests regenerate all fixtures at test time from a seeded RNG
(random hex, base58check-alphabet WIF shapes, BIP-39 wordlist subset
mnemonics) — no real credential is embedded anywhere. Sensitive
categories must be flagged; public wallet addresses, hash-like hex
(SHA-256/git SHA/SHA-512), unlabeled hex and prose must produce zero
findings. Dogfood tests scan an env-provided tree (LEFTBLOCK_DOGFOOD_TREE)
and honor that tree&#39;s .gitleaksignore entries. BDD scenarios cover a
real leftblock install: default config blocks a staged synthetic key,
allows clean commits, and does not flag public addresses/digests. ([`1dc1537`](https://github.com/DataParade-io/LeftBlock/commit/1dc153710d2d204682cf077aed8aef0db45e30db))

### Unknown

* Merge pull request #3 from AnthusAI/develop

Release: promote develop to main (out-of-the-box sensitive-data detection) ([`204f285`](https://github.com/DataParade-io/LeftBlock/commit/204f285d6406d66fa2c801a463d63f199eac7329))

* Merge pull request #2 from AnthusAI/cursor/ootb-detection-b3b8

feat: out-of-the-box sensitive-data detection rules + default config wiring ([`759598d`](https://github.com/DataParade-io/LeftBlock/commit/759598dff42adf4b282fea38e450db11539d253e))

## v0.1.2 (2026-08-31)

### Fix

* fix: pin hook Python interpreter and PATH for command checkers (#1)

Git runs commit-msg with a stripped PATH, so `leftblock` and Homebrew
gitleaks were often missing. Install now writes a hook that execs the
install-time Python, prepends that PATH, and targets the shared Git
hooks directory so linked worktrees get the same hook. ([`62bafe6`](https://github.com/DataParade-io/LeftBlock/commit/62bafe640e9301843046ec5ff615fdb7a8ee2098))

## v0.1.1 (2026-08-31)

### Fix

* fix: add pypa/gh-action-pypi-publish step to actually upload to PyPI ([`c839332`](https://github.com/DataParade-io/LeftBlock/commit/c839332fa422e00d59df9f06cc70efc5d35946af))

## v0.1.0 (2026-08-31)

### Ci

* ci: add GitHub Actions and semantic-release configuration ([`d929cff`](https://github.com/DataParade-io/LeftBlock/commit/d929cff2875a123bffc10d1a9aa5f7e4ab25240c))

### Documentation

* docs: emphasize shifting left and catching secrets before commit ([`5c4dfd8`](https://github.com/DataParade-io/LeftBlock/commit/5c4dfd8a27e15077709a1529e5d716b98668eb96))

* docs: fix mermaid syntax errors ([`369e83b`](https://github.com/DataParade-io/LeftBlock/commit/369e83b1897d467ead307c8d6932f37c425bd506))

* docs: add high-level flow diagram, quick-start, and Tactus examples ([`3bcd7a9`](https://github.com/DataParade-io/LeftBlock/commit/3bcd7a951ba7374a97f089619c743c386113873c))

* docs: use more professional language for HMAC secret ([`ab01f58`](https://github.com/DataParade-io/LeftBlock/commit/ab01f582d5b7a70292c4ea416beb0699895d7e31))

* docs: rewrite README with architecture diagrams and better explanations ([`c50ece5`](https://github.com/DataParade-io/LeftBlock/commit/c50ece584c23a1be94e9dd65103cb0cfcc63c84a))

### Feature

* feat: initial release ([`dda0b5e`](https://github.com/DataParade-io/LeftBlock/commit/dda0b5eddf1e4d57b4e6addf79e93817a54d82ea))

* feat: add retroactive approve command and pooling verify ([`9bc6df0`](https://github.com/DataParade-io/LeftBlock/commit/9bc6df0c008631c694a5d41bdc751169903e3e02))

* feat: initial leftblock structure ([`9283833`](https://github.com/DataParade-io/LeftBlock/commit/9283833732f237de0a2015cac517e591df206f42))

### Fix

* fix: explicit package discovery for setuptools to ignore features dir ([`6f9cfd3`](https://github.com/DataParade-io/LeftBlock/commit/6f9cfd3a66214002003a5771beb399dd408c0626))

### Test

* test: add behave gherkin specs ([`e351337`](https://github.com/DataParade-io/LeftBlock/commit/e351337297cfa9bd7454cbca0c237e298209478d))
