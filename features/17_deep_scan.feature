Feature: Deep scan
  As a developer or CI maintainer who wants a second opinion beyond pattern rules
  I want an optional, model-based scan of what I am about to commit or merge
  So that personal data and secrets with no fixed shape are caught, without slowing every commit

  "leftblock deep-scan" reads the added lines of the staged diff (or, with
  --range A..B, of the commits in that range, for CI) with OpenAI's Privacy
  Filter, a token-classification model. It is optional (the leftblock[deep]
  extra), slow and heavy, so the commit hook never runs it: the hook stays on
  gitleaks. By default it reports secrets, emails, phone numbers and addresses
  the model is at least 0.9 sure of; names, account numbers, dates and links
  are off until asked for. A set of exclusions removes the noise a model
  makes (board data, generated files, identifier shapes, placeholder lines,
  allowed addresses). It exits like "check", honours recorded overrides under
  the rule name "privacy-filter-<label>", and never prints the matched value.
  These specs replace the model with a stub detector that recognises the
  synthetic values each scenario creates.

  # --- Installing and running ------------------------------------------------

  Scenario: Without the optional extra the scan explains how to install it
    Given a repository without LeftBlock
    And the deep scan extra is not installed
    When I run "leftblock deep-scan"
    Then the exit code is 2
    And stderr contains "pip install 'leftblock[deep]'"

  Scenario: A staged credential is reported by location, rule, id and score
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I run "leftblock deep-scan"
    Then the exit code is 1
    And a finding is reported at "settings.cfg" line 1 for rule "privacy-filter-secret" with score 0.97
    And stderr contains "leftblock allow --deep"
    And the output does not reveal the synthetic value

  Scenario: Staged changes the model finds nothing in pass
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

  Scenario: Only staged changes are scanned, not committed history or unstaged edits
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "old.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    And the file "old.cfg" is committed
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

  # --- Labels and threshold --------------------------------------------------

  Scenario Outline: Four labels are reported by default
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "data.cfg" containing a <kind> that the model flags as <label> at 0.95
    When I run "leftblock deep-scan"
    Then the exit code is 1
    And a finding is reported at "data.cfg" line 1 for rule "privacy-filter-<label>" with score 0.95

    Examples:
      | kind                   | label           |
      | credential-shaped value | secret          |
      | work email             | private_email   |
      | phone number           | private_phone   |
      | street address         | private_address |

  Scenario Outline: Four labels are off until enabled
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "data.cfg" containing a <kind> that the model flags as <label> at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

    Examples:
      | kind          | label          |
      | person name   | private_person |
      | account number | account_number |
      | birth date    | private_date   |
      | profile link  | private_url    |

  Scenario Outline: An off label is enabled with --labels
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "data.cfg" containing a <kind> that the model flags as <label> at 0.99
    When I run "leftblock deep-scan --labels <label>"
    Then the exit code is 1
    And a finding is reported at "data.cfg" line 1 for rule "privacy-filter-<label>" with score 0.99

    Examples:
      | kind          | label          |
      | person name   | private_person |
      | account number | account_number |
      | birth date    | private_date   |
      | profile link  | private_url    |

  Scenario: Enabling one extra label keeps the default ones
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "a.cfg" containing a credential-shaped value that the model flags as secret at 0.95
    And a staged file "b.cfg" containing a person name that the model flags as private_person at 0.95
    When I run "leftblock deep-scan --labels private_person"
    Then the exit code is 1
    And 2 findings are reported

  Scenario: An unknown label is a usage error
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    When I run "leftblock deep-scan --labels not_a_label"
    Then the exit code is 2
    And stderr contains "Unknown label"

  Scenario: A score exactly at the default threshold is reported
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.9
    When I run "leftblock deep-scan"
    Then the exit code is 1

  Scenario: A score below the default threshold is not reported
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.89
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

  Scenario: A higher threshold hides what the model is less sure of
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.93
    When I run "leftblock deep-scan --threshold 0.95"
    Then the exit code is 0

  Scenario: A lower threshold shows what the model is less sure of
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.6
    When I run "leftblock deep-scan --threshold 0.5"
    Then the exit code is 1
    And a finding is reported at "settings.cfg" line 1 for rule "privacy-filter-secret" with score 0.60

  Scenario: A threshold outside 0 to 1 is a usage error
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    When I run "leftblock deep-scan --threshold 7"
    Then the exit code is 2
    And stderr contains "--threshold"

  # --- Exclusions ---------------------------------------------------------------

  Scenario Outline: Kanbus board data is skipped without asking the model
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "<path>" containing a credential-shaped value that the model flags as secret at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And the model was never consulted

    Examples:
      | path                              |
      | project/issues/abc123.json        |
      | project/events/abc123.jsonl       |
      | sub/project/issues/abc123.json    |
      | project/.cache/index.json         |

  Scenario: Other files under project are still scanned
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "project/notes.json" containing a credential-shaped value that the model flags as secret at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 1

  Scenario Outline: Generated, minified, vendored and lock files are skipped
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "<path>" containing a credential-shaped value that the model flags as secret at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And the model was never consulted

    Examples:
      | path                        |
      | package-lock.json           |
      | web/pnpm-lock.yaml          |
      | poetry.lock                 |
      | go.sum                      |
      | assets/app.min.js           |
      | assets/app.js.map           |
      | node_modules/lib/index.js   |
      | vendor/lib/client.go        |
      | api/service_pb2.py          |
      | src/schema.generated.ts     |
      | pkg/__pycache__/mod.pyc     |

  Scenario Outline: A secret shaped like an identifier is skipped
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "build.cfg" containing a <kind> that the model flags as secret at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

    Examples:
      | kind                |
      | UUID-shaped value   |
      | hex digest value    |
      | hex colour value    |
      | ISO timestamp value |
      | issue id value      |

  Scenario Outline: A line marked as a placeholder, example, fake or dummy is skipped
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a <word>-marked credential that the model flags as secret at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

    Examples:
      | word        |
      | placeholder |
      | example     |
      | fake        |
      | synthetic   |
      | dummy       |

  Scenario Outline: An email address that is already allowed is skipped
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "contacts.cfg" containing a <kind> that the model flags as private_email at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported

    Examples:
      | kind                  |
      | reserved-domain email |
      | noreply email         |
      | internal email        |

  Scenario: A personal email address is reported
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "contacts.cfg" containing a work email that the model flags as private_email at 0.99
    When I run "leftblock deep-scan"
    Then the exit code is 1

  # --- Recorded overrides -------------------------------------------------------

  Scenario: A recorded override clears a deep-scan finding and is reported
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I note the finding ids from a deep scan
    And I record a deep scan override for the noted findings because "Public build token for the sandbox"
    Then the exit code is 0
    And the staged allow file records rule "privacy-filter-secret" for "settings.cfg"
    When I run "leftblock deep-scan"
    Then the exit code is 0
    And no finding is reported
    And stderr contains "Override applied"
    And stderr contains "privacy-filter-secret"

  Scenario: Changing the approved line blocks it again
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I note the finding ids from a deep scan
    And I record a deep scan override for the noted findings because "Public build token for the sandbox"
    And the flagged line in "settings.cfg" is reworded and staged
    And I run "leftblock deep-scan"
    Then the exit code is 1

  Scenario: An id that is not a current deep-scan finding is refused
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I run "leftblock allow --deep 0000000000000000 --reason 'Public build token for the sandbox'"
    Then the exit code is 1
    And stderr contains "Not a current deep-scan finding id"

  Scenario: An invalid allow file is an error, not a pass
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file ".leftblock-allow.yml" containing:
      """
      allow: nonsense
      """
    When I run "leftblock deep-scan"
    Then the exit code is 2
    And stderr contains "Invalid .leftblock-allow.yml"

  # --- Output -------------------------------------------------------------------

  Scenario: JSON output carries the same facts and never the value
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I run "leftblock deep-scan --format json"
    Then the exit code is 1
    And stdout is valid JSON with "result" equal to "blocked"
    And stdout is valid JSON with "findings.0.file" equal to "settings.cfg"
    And stdout is valid JSON with "findings.0.line" equal to "1"
    And stdout is valid JSON with "findings.0.rule" equal to "privacy-filter-secret"
    And stdout is valid JSON with "findings.0.score" equal to "0.97"
    And the output does not reveal the synthetic value

  Scenario: JSON output for a clean scan says passed
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    When I run "leftblock deep-scan --format json"
    Then the exit code is 0
    And stdout is valid JSON with "result" equal to "passed"

  Scenario: A missing extra is a JSON error too
    Given a repository without LeftBlock
    And the deep scan extra is not installed
    When I run "leftblock deep-scan --format json"
    Then the exit code is 2
    And stdout is valid JSON with "result" equal to "error"

  Scenario: A recorded override is listed in the JSON result
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I note the finding ids from a deep scan
    And I record a deep scan override for the noted findings because "Public build token for the sandbox"
    And I run "leftblock deep-scan --format json"
    Then the exit code is 0
    And stdout is valid JSON with "overrides_applied.0.rule" equal to "privacy-filter-secret"
    And the output does not reveal the synthetic value

  Scenario: The output has no colour codes when captured
    Given a repository without LeftBlock
    And NO_COLOR is not set
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I run "leftblock deep-scan"
    Then the exit code is 1
    And the output has no ANSI escape codes

  Scenario: The output has no colour codes when NO_COLOR is set
    Given a repository without LeftBlock
    And NO_COLOR is set
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I run "leftblock deep-scan"
    Then the output has no ANSI escape codes

  # --- Commit ranges (CI) ---------------------------------------------------------

  Scenario: A range scans the added lines of the commits in it
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    And the file "settings.cfg" is committed
    When I run "leftblock deep-scan --range HEAD~1..HEAD"
    Then the exit code is 1
    And a finding is reported at "settings.cfg" line 1 for rule "privacy-filter-secret" with score 0.97
    And the output does not reveal the synthetic value

  Scenario: A range leaves out commits before it and staged changes
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "old.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    And the file "old.cfg" is committed
    And the file "notes.txt" is committed
    And a staged file "new.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    When I run "leftblock deep-scan --range HEAD~1..HEAD"
    Then the exit code is 0
    And no finding is reported

  Scenario: A secret added and removed within the range is still reported
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    And the file "settings.cfg" is committed
    And the file "settings.cfg" is deleted and committed
    When I run "leftblock deep-scan --range HEAD~2..HEAD"
    Then the exit code is 1

  Scenario: A range applies the same exclusions
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "project/issues/abc123.json" containing a credential-shaped value that the model flags as secret at 0.97
    And the file "project/issues/abc123.json" is committed
    When I run "leftblock deep-scan --range HEAD~1..HEAD"
    Then the exit code is 0
    And the model was never consulted

  Scenario: A range reports in JSON like the staged scan
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.97
    And the file "settings.cfg" is committed
    When I run "leftblock deep-scan --range HEAD~1..HEAD --format json"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.rule" equal to "privacy-filter-secret"
    And the output does not reveal the synthetic value

  Scenario: A range that is not a range is an error
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    When I run "leftblock deep-scan --range HEAD"
    Then the exit code is 2
    And stderr contains "--range must look like A..B"

  Scenario: A range naming an unknown revision is an error
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    When I run "leftblock deep-scan --range nothere..HEAD"
    Then the exit code is 2

  # --- Exit codes and the hook ---------------------------------------------------

  Scenario: Outside a Git repository the scan is an error
    Given the deep scan model is replaced by a stub detector
    When I run "leftblock deep-scan"
    Then the exit code is 2
    And stderr contains "Not inside a Git repository"

  @gitleaks
  Scenario: The commit hook never runs the deep scan
    Given a repository with LeftBlock installed as a local check-only gate
    And the deep scan model is replaced by a stub detector
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit succeeds
    And the model was never consulted

  Scenario: The dry run of a commit does not run the deep scan either
    Given a repository without LeftBlock
    And the deep scan model is replaced by a stub detector
    And a staged file "settings.cfg" containing a credential-shaped value that the model flags as secret at 0.99
    When I run "leftblock check"
    Then the model was never consulted
