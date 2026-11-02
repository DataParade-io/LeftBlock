# LeftBlock behaviour specs

These Gherkin specs are the behavioural source of truth for LeftBlock: they
describe, in user terms, what the tool does and why. `tests/` holds the finer
grained unit tests (rule corpora, edge cases, internals); when the two seem to
disagree, the specs say what the behaviour is meant to be.

The chapters read in order, as one story, and live in `features/NN_slug.feature`.
Run them with `behave` from the repository root (gitleaks on PATH; scenarios
tagged `@gitleaks` are skipped without it). Step vocabulary and rules for
authors are in [steps/README.md](steps/README.md).

1. **Installing the local gate** (`01_installing_the_local_gate`). A developer
   adds a pre-commit gate to one repository with a single command. It touches
   only Git metadata, creates no secret and no tracked files, keeps existing
   hooks, refuses to overwrite foreign or edited ones, and can be re-run.
2. **Stable runtime and upgrades** (`02_stable_runtime_and_upgrades`). Hooks run
   through a stable link to the installed environment, so upgrading once
   upgrades every repository, and a broken link fails closed with
   reinstall instructions.
3. **Blocking sensitive commits** (`03_blocking_sensitive_commits`). The core
   promise: a commit with sensitive staged data is stopped before it exists,
   HEAD stays put, the rule is named and the value is never repeated; clean
   commits and unstaged changes are unaffected.
4. **What LeftBlock detects** (`04_what_leftblock_detects`). The shipped rules
   out of the box: personal data, identifiers, cloud and wallet secrets, and
   the public look-alikes (addresses, digests) that must not be flagged.
5. **AI provider keys** (`05_ai_provider_keys`). Keys of the common AI
   providers are recognised by their format, or by a provider-named variable;
   references and placeholders are not keys.
6. **Kanbus board data** (`06_kanbus_board_data`). Identifiers in Kanbus issue
   and event files are accepted so the tracker never blocks, while emails,
   home paths and keys inside them are still caught.
7. **Reading a block** (`07_reading_a_block`). What a developer sees when a
   commit is blocked: version and ruleset, findings by file and line, what to
   do next, and the dry-run command to re-run.
8. **Dry run and machine output** (`08_dry_run_and_machine_output`).
   `leftblock check` previews the next commit without changing anything, with
   documented exit codes and a JSON result for tools.
9. **Recorded overrides** (`09_recorded_overrides`). A false alarm is cleared
   with `leftblock allow`, which needs a reason, is committed, reviewable and
   reported every time it applies.
10. **Silent bypasses** (`10_silent_bypasses`). Ways around a scanner (inline
    allow comments, ignore files) are not honoured silently: they are reported
    or require a recorded override.
11. **Failing closed** (`11_failing_closed`). A missing scanner, broken policy
    or checker error blocks the commit rather than letting it through.
12. **Merge commits** (`12_merge_commits`). Merges are inspected for what the
    merge itself introduces, not for everything inherited from either parent.
13. **Receipt mode** (`13_receipt_mode`). The optional mode that stamps each
    clean commit with a signed receipt and verifies it later.
14. **Retroactive approval** (`14_retroactive_approval`). Unsigned history can
    be approved after the fact by a new commit, without rewriting anything.
15. **Custom checkers** (`15_custom_checkers`). Receipt-mode policy can run any
    command as a checker with its own success and finding codes.
16. **The command line** (`16_the_command_line`). Subcommands, `--help`,
    `--version` and argument errors: the surface a person types.
17. **Deep scan** (`17_deep_scan`). The optional, model-based
    `leftblock deep-scan` (never run by the hook): default labels and
    threshold, enabling off labels, the exclusions, recorded overrides,
    `--range` for CI, exit codes, and never printing the matched value. The
    specs swap the model for a stub detector.
18. **Measuring detection** (`18_measuring_detection`). The evaluation harness in
    `eval/` (not packaged, never run in full by CI): recall and precision of
    stock gitleaks, the shipped ruleset, the deep scan and their combination over
    labelled lines, with Wilson intervals, a critical tier of credential
    categories, X-labelled lines excluded and counted, flags on unlabelled lines
    kept apart, the deep scan reading windows around a sample, reports free of
    values and paths, and a data directory that must sit outside any Git
    repository. The specs build a tiny CredData-shaped dataset at run time and
    swap the model for the stub detector.
    The same chapter specs running it from a fresh clone: the prerequisite
    check and its fixes, the pinned gitleaks (another version is refused
    or, if allowed, warned about and recorded), every input recorded in the
    results, `reproduce` with its resumable deep scan and smoke runs, and
    `compare`.
19. **Scanning text outside git** (`19_scanning_text`). `leftblock scan` runs the
    shipped rules and post-filters (the WIF checksum) over text with no Git
    behind it: JSONL records on stdin with findings as UTF-8 byte offsets
    (multi-byte text and multi-line records checked by slicing, and the
    one-column shift gitleaks applies to later lines corrected), or files and
    directories in text or JSON. Finding ids match the hook's, recorded
    overrides are not applied, no value is ever printed, the records live in
    an owner-only temporary folder that gitleaks reads in one run and that is
    removed even on failure, and `--deep` adds the model (stubbed in the
    specs). Exit codes 0, 1 and 2, malformed lines, empty input, and running
    outside a repository.
20. **Receipts for a local CI run** (`20_ci_receipts`). `leftblock ci` runs the
    repository's `ci.command` on a clean tree at exactly HEAD, writes a receipt
    to `.git/leftblock/receipts/<sha>.json` (optionally HMAC-signed with the
    shared secret) and posts the `leftblock/ci` commit status with `gh`,
    failure included, so a deploy can refuse an untested or red commit. Dirty
    trees, other commits and missing policy are refused with status 2;
    `--no-status` and `--dry-run` post nothing. `gh` is a recording stand-in
    in the specs.
