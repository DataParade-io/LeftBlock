Feature: Receipts for a local CI run
  As a team whose private repositories run CI on a laptop instead of in paid build minutes
  I want one command that runs the repository's CI on an exact commit and leaves proof of the result
  So that a deploy can refuse a commit that nobody tested, or that failed its tests

  "leftblock ci" reads the "ci" section of .leftblock.yml: "command" is the one
  shell command the repository calls its CI, "status_context" names the GitHub
  commit status (default leftblock/ci) and "sign" asks for an HMAC signature
  made with the shared LeftBlock secret. The run is refused unless the work
  tree is clean and the commit asked for (--sha, default HEAD) is HEAD, so the
  receipt is for exactly what was tested. The command runs with its output
  streamed. A receipt is written to .git/leftblock/receipts/<sha>.json with the
  sha, tree, the checks, the result (success or failure), start and finish
  times, tool versions, the LeftBlock version and the host. When signing, the
  signature is hmac-sha256 over "sha|tree|result|finished_at". Unless
  --no-status is given, the result is posted with "gh api" as a commit status,
  failure included, so a deploy gate sees red. The exit status is the CI
  command's; a refusal exits 2. The receipt guards against mistakes, such as
  forgetting to run the checks or deploying a red commit. It does not guard
  against a malicious committer: anyone holding the GitHub token can post the
  status and anyone holding the secret can sign.

  # --- A passing run ----------------------------------------------------------

  Scenario: A passing run on a clean tree writes a receipt and posts a success status
    Given a repository whose committed policy runs the CI command "true"
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci"
    Then the exit code is 0
    And the receipt for HEAD says the result is "success"
    And the receipt for HEAD records the exact commit and tree
    And the receipt for HEAD records one check "true" with exit code 0
    And the receipt for HEAD names the tool versions, the host and the finish time
    And the receipt for HEAD has no signature
    And the commit status posted for HEAD has state "success" and context "leftblock/ci"

  Scenario: The status description summarizes the result and the number of checks
    Given a repository whose committed policy runs the CI command "true"
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci"
    Then the posted status description starts with "success 1 checks"

  Scenario: The CI command's output is streamed
    Given a repository whose committed policy runs the CI command "echo checks are running"
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci"
    Then stdout contains "checks are running"

  # --- A failing run ----------------------------------------------------------

  Scenario: A failing command still posts a failure status and exits non-zero
    Given a repository whose committed policy runs the CI command "exit 3"
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci"
    Then the exit code is 3
    And the receipt for HEAD says the result is "failure"
    And the receipt for HEAD records one check "exit 3" with exit code 3
    And the commit status posted for HEAD has state "failure" and context "leftblock/ci"

  Scenario: A status that cannot be posted is reported and the run fails
    Given a repository whose committed policy runs the CI command "true"
    And the GitHub CLI is replaced by a stand-in that refuses
    When I run "leftblock ci"
    Then the exit code is 1
    And stderr contains "Posting the commit status failed"
    And the receipt for HEAD says the result is "success"

  # --- Refusals ---------------------------------------------------------------

  Scenario: A dirty work tree is refused and nothing runs
    Given a repository whose committed policy runs the CI command "touch ci-ran"
    And the GitHub CLI is replaced by a recording stand-in
    And an uncommitted change to "notes.txt"
    When I run "leftblock ci"
    Then the exit code is 2
    And stderr contains "not clean"
    And the CI command did not run
    And there is no receipt for HEAD
    And no commit status was posted

  Scenario: A commit other than HEAD is refused
    Given a repository whose committed policy runs the CI command "touch ci-ran"
    And the GitHub CLI is replaced by a recording stand-in
    And a second commit is made
    When I run "leftblock ci --sha HEAD~1"
    Then the exit code is 2
    And stderr contains "is not HEAD"
    And the CI command did not run
    And no commit status was posted

  Scenario: A repository without a ci command is refused
    Given a repository without LeftBlock
    When I run "leftblock ci"
    Then the exit code is 2
    And stderr contains "ci.command"

  # --- Offline and dry runs ---------------------------------------------------

  Scenario: --no-status writes the receipt and posts nothing
    Given a repository whose committed policy runs the CI command "true"
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci --no-status"
    Then the exit code is 0
    And the receipt for HEAD says the result is "success"
    And no commit status was posted

  Scenario: --dry-run runs nothing, writes nothing and posts nothing
    Given a repository whose committed policy runs the CI command "touch ci-ran"
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci --dry-run"
    Then the exit code is 0
    And stdout contains "dry run"
    And the CI command did not run
    And there is no receipt for HEAD
    And no commit status was posted

  # --- Signing ----------------------------------------------------------------

  Scenario: A signed receipt carries an HMAC that the status description echoes
    Given a repository whose committed policy runs the CI command "true" with signing on
    And a LeftBlock signing secret exists
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci"
    Then the exit code is 0
    And the receipt for HEAD has a valid signature over sha, tree, result and finish time
    And the posted status description ends with the first 12 hex digits of the signature

  Scenario: Signing without a secret is refused before anything runs
    Given a repository whose committed policy runs the CI command "touch ci-ran" with signing on
    And the GitHub CLI is replaced by a recording stand-in
    When I run "leftblock ci"
    Then the exit code is 2
    And stderr contains "ci.sign"
    And the CI command did not run
    And no commit status was posted
