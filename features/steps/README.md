# Step vocabulary

Steps are written declaratively, in the present tense ("the commit is
blocked"). The shared ones live in `common_steps.py`; helpers live in
`features/world.py` and synthetic values in `features/synthetic_data.py`
(both outside `steps/`, so behave loads them once). `features/environment.py`
gives every scenario a temporary root with its own HOME, LEFTBLOCK_HOME and
signing-secret path (`context.env`), sets NO_COLOR, strips `GIT_*`
variables and removes everything afterwards.

State on `context`: `repo` (path), `result` (`returncode`, `stdout`,
`stderr` of the last command), `env`, `home`, `leftblock_home`,
`secret_path`, `synthetic_values`, `head_before`.

## Common steps (never redefine)

Given
- `a repository without LeftBlock`: git repo, one empty commit.
- `a repository with LeftBlock installed as a local check-only gate`: runs
  `python -m leftblock.cli install --local --check-only --gitleaks <gitleaks>`.
  If gitleaks is absent a stand-in executable is used, so install-only
  scenarios still run.
- `a repository with LeftBlock installed in receipt mode`: runs plain
  `leftblock install` (commit-msg hook, `.leftblock.yml`, `.leftblock/`
  staged, secret at `context.secret_path`).
- `a staged file "{name}" containing:` (docstring, dedented; no sensitive literals).
- `a staged file "{name}" containing a synthetic {kind}`
- `an unstaged change to "{name}" containing a synthetic {kind}` (appended, not staged).
- `the file "{name}" is committed`: commits staged work plus `name` with
  `--no-verify` (setup only; creates `name` as harmless text if it is absent).

When
- `I commit the staged files`: `git commit -m "test: staged content"`; hooks run.
- `I run "leftblock {args}"`: `python -m leftblock.cli` in the repo, args split
  like a shell, stdin closed (no TTY).

Then
- `the commit is blocked` (nonzero exit) / `the commit succeeds` (zero exit and HEAD moved)
- `HEAD has not moved` (since the last When)
- `the exit code is {n}`
- `stderr contains "{text}"` / `stderr does not contain "{text}"`
- `stdout contains "{text}"` / `stdout does not contain "{text}"`
- `stdout is valid JSON with "{field}" equal to "{value}"`: dotted path,
  e.g. `findings.0.rule`; compared as text (`null`, `true`).
- `the output does not reveal the synthetic value`: no generated secret
  appears in stdout or stderr.

Hook output (including a block) arrives on stderr of the commit.

## Receipt steps (`receipt_steps.py`, chapters 13 and 14)

- `a commit made without the hook` / `{n} unsigned commits` /
  `an unsigned commit containing a synthetic {kind}` (all `--no-verify`)
- `the latest commit message contains "{text}"` / `... does not contain "{text}"`

## Deep scan steps (`ch17_deep_scan_steps.py`, chapter 17)

The model is never downloaded in specs: `LEFTBLOCK_DEEP_DETECTOR` names
`features/stub_detector.py`, which flags the values these steps register.

- `the deep scan model is replaced by a stub detector` /
  `the deep scan extra is not installed`
- `a staged file "{name}" containing a {kind} that the model flags as {label} at {score}`
  (kinds are listed in the step module, e.g. `credential-shaped value`,
  `work email`, `UUID-shaped value`, `<word>-marked credential`)
- `the file "{name}" is deleted and committed`,
  `the flagged line in "{name}" is reworded and staged`
- `I note the finding ids from a deep scan`,
  `I record a deep scan override for the noted findings because "{reason}"`
- `a finding is reported at "{name}" line {n} for rule "{rule}" with score {score}`,
  `no finding is reported`, `{n} findings are reported`
- `the model was never consulted` / `the model was consulted`,
  `the output has no ANSI escape codes`,
  `the staged allow file records rule "{rule}" for "{name}"`

## Measuring detection steps (`ch18_measuring_steps.py`, chapter 18)

A CredData-shaped fixture is built at run time (`eval-data/CredData/{meta,data}`
in the scenario's world); `python -m eval run` is run as a subprocess with the
stub detector, and `context.results` holds the parsed results JSON.

- `a fixture dataset`
- `the fixture labels these lines:` (table `truth | category | shape`; shapes:
  `ruleset key`, `model-only secret`, `pem block`, `quiet value`, `uuid`)
- `the fixture also holds an unlabelled file with a ruleset key`
- `the model flags the fixture's model-only secrets as secret at {score}`
- `I evaluate the fixture with detectors "{names}"` (and
  `... and a deep sample of {n}`), `I evaluate the generated corpus with detectors "{names}"`,
  `I evaluate with the data directory inside that repository`
- `the evaluation succeeds`
- `in the {full files|deep sample} "{detector}" scores {tp} true positives, {fp} false positives and {fn} misses`
  and `... has recall {r} and precision {p}` (detectors: `stock gitleaks`,
  `LeftBlock ruleset`, `deep scan`, `combined`)
- `in the {scope} the critical tier holds {n} true lines and "{detector}" misses {m} of them`
- `{n} labelled lines are excluded as X`,
  `{n} findings on unlabelled lines are reported for "{detector}" apart from the scores`
- `the deep scan adds {tp} true positives and {fp} false positives over the LeftBlock ruleset`,
  `the deep sample holds {n} critical true lines`,
  `the deep sample estimates {n} false lines from {m} sampled`
- `every reported rate has a 95% interval around it`,
  `the report reveals no fixture value or file path`,
  `the report states the critical tier and the excluded count`,
  `the generated corpus had more than {n} labelled lines`,
  `the generated corpus left no files behind`, `the report reveals no generated value`

## Synthetic kinds

Used as `a synthetic <kind>`. The content shown is what ends up in the file.

- Personal data: `personal email`, `home path`, `Windows home path`,
  `session UUID`, `actor id`.
- Cloud: `AWS key pair`.
- AI providers, prefixed (written as `client_credential = "<key>"`):
  `OpenAI key`, `OpenAI admin key`, `Anthropic key`, `Groq key`, `xAI key`,
  `Replicate key`, `Together AI key`, `OpenRouter key`, `Fireworks key`,
  `Cerebras key`, `LangSmith key`, `ElevenLabs key`, `Voyage AI key`,
  `Pinecone key`. In the feature file the provider is the word before "key",
  so `a synthetic <provider> key` works in outlines.
- AI providers, unprefixed (written as `PROVIDER_API_KEY=<value>`):
  `Mistral key`, `Cohere key`, `Azure OpenAI key`, `Deepgram key`,
  `Together AI legacy key`.
- Wallets: `Ethereum private key`, `Bitcoin WIF key`, `seed phrase`.
- Must not be flagged: `harmless code`, `public wallet address and digest`.

## Rules for chapter authors

1. Put new steps in `features/steps/chNN_<slug>_steps.py`. Do not edit
   `common_steps.py`, `receipt_steps.py` (unless you own 13/14) or `world.py`
   except to add a helper; reuse them with `import world`.
2. Never redefine a common step. Behave fails on ambiguous steps, so phrase
   chapter-specific steps distinctively (a verb or noun only your chapter
   uses), and do not make a pattern that also matches a common step.
3. Add new synthetic kinds from your own step module with
   `from synthetic_data import generator, token` and
   `@generator("kind name")`; kind names must be unique. Never write a
   literal secret, email, home path or UUID anywhere in the repository: the
   repo's own pre-commit hook and CI scan every file. Build values at run
   time (split prefixes as the generators do).
4. Tag every scenario (or feature) that really scans with `@gitleaks`.
5. Keep scenarios behavioural: Given/When/Then in user terms, one behaviour
   per scenario, a narrative header ("As a ... I want ... So that ...") and
   a short description of the chapter.
6. Run `behave` from a venv with `pip install -e . behave`; scenarios must be
   independent (each gets a fresh temporary world).
