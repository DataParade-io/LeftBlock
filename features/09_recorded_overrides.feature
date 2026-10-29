Feature: Recorded overrides
  As a developer who hit a false alarm
  I want to approve one finding with a written reason that is committed and reviewed
  So that a block never has to be bypassed silently, and every exception stays visible

  A block is the default. A false alarm (a public role address in a privacy
  notice, say) is cleared with "leftblock allow <id> --reason ...". That records
  one entry in ".leftblock-allow.yml" and stages the file, but never commits.
  Only the staged version counts, so the exception is always part of the commit
  and its review. An entry approves one reviewed value: one rule matching one
  exact value in one file. Changing the matched value, or adding another
  finding, blocks again; editing the rest of the line does not, so a reviewed
  false alarm does not come back each time unrelated text beside it changes.
  The same value flagged by the same rule on several lines of a file is one
  reviewed value, and one entry covers all of those lines. Entries recorded by
  earlier versions identified the whole line; they still apply to a line that
  has not changed. Every check
  prints each override it applied with its reason. Invalid allow files fail
  closed, and errors (as opposed to findings) can never be overridden.

  @gitleaks
  Scenario: A blocked check offers the override command and never the value
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    Then every noted finding id appears in the output
    And stderr contains "record a reviewed override"
    And stderr contains "--reason"
    And the output does not reveal the synthetic value

  @gitleaks
  Scenario: The final line alone names the finding and the next step
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    Then the final line of the output names the finding and its next step

  @gitleaks
  Scenario: Recording an override writes a reviewable entry and stages it
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    Then the exit code is 0
    And the staged allow file has an entry for rule "leftblock-personal-email" in "page.tsx" with the reason "Public role address for the site"
    And the staged allow file does not contain any flagged value

  @gitleaks
  Scenario: Recording an override does not commit anything
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    Then the allow file is staged and nothing was committed
    And stderr contains "is staged; the commit must include it"

  @gitleaks
  Scenario: The entry records the category of the finding for reviewers
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    Then the staged allow file entry records the category "Personal email address"

  @gitleaks
  Scenario: The category is informational and not needed for matching
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And the allow file has its category line removed by hand and is staged
    And I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: After the override the commit passes
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I commit the staged files
    Then the commit succeeds

  @gitleaks
  Scenario: Every check announces each applied override with its reason
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I run "leftblock check"
    Then the exit code is 0
    And stderr contains "Override applied"
    And stderr contains "leftblock-personal-email"
    And stderr contains "Public role address for the site"
    And every noted finding id appears in the output

  @gitleaks
  Scenario: Overrides keep being announced on later checks
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I run "leftblock check"
    And I run "leftblock check"
    Then stderr contains "Override applied"

  @gitleaks
  Scenario: An override covers a finding in a file that was already committed
    Given a repository with LeftBlock installed as a local check-only gate
    And a committed file "page.tsx" of three plain lines
    And I extend "page.tsx" with a personal address and stage it
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: A new finding in the same file still blocks
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I add a second personal address to "page.tsx" and stage it
    And I run "leftblock check"
    Then the exit code is 1
    And exactly 1 finding is listed
    And the noted finding ids no longer appear in the findings

  @gitleaks
  Scenario: Unrelated edits to the rest of an approved line keep it approved
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I add text around the flagged address in "page.tsx" and stage it
    And I run "leftblock check"
    Then the exit code is 0
    And stderr contains "Override applied"

  @gitleaks
  Scenario: Reworded text beside an approved value keeps it approved
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I reword the flagged line of "page.tsx" and stage it
    And I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: Changing the approved value blocks it again
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I replace the flagged address in "page.tsx" with another personal address and stage it
    And I run "leftblock check"
    Then the exit code is 1
    And exactly 1 finding is listed
    And the noted finding ids no longer appear in the findings

  @gitleaks
  Scenario: One override covers the same value on two lines of a file
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    And I add the flagged address to "page.tsx" again on another line and stage it
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    Then the staged allow file records 1 override
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: Recording an override stores an id of the rule, the file and the value alone
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    Then the staged allow file entry for "page.tsx" has the id of its rule and the flagged value alone

  @gitleaks
  Scenario: An entry recorded by an earlier version still allows an unchanged line
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    And I replace the staged allow file with a line-based entry for rule "leftblock-personal-email" on the flagged line of "page.tsx"
    When I run "leftblock check"
    Then the exit code is 0
    And stderr contains "Override applied"
    And every override that applied is reported under its recorded id

  @gitleaks
  Scenario: An entry recorded by an earlier version blocks again when its line changes
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    And I replace the staged allow file with a line-based entry for rule "leftblock-personal-email" on the flagged line of "page.tsx"
    When I reword the flagged line of "page.tsx" and stage it
    And I run "leftblock check"
    Then the exit code is 1

  @gitleaks
  Scenario: The same text in another file is not approved
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I stage a copy of the flagged line in "other.tsx"
    And I run "leftblock check"
    Then the exit code is 1
    And exactly 1 finding is listed

  @gitleaks
  Scenario: An allow file that is not staged has no effect
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I unstage the allow file
    And I run "leftblock check"
    Then the exit code is 1
    And the working allow file is not staged

  @gitleaks
  Scenario: Several findings are overridden in one command
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    And I add a second personal address to "page.tsx" and stage it
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role addresses for the site"
    Then the exit code is 0
    And the staged allow file records 2 overrides
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: Recording the same override twice keeps a single entry
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings twice
    Then the staged allow file records 1 override
    When I run "leftblock check"
    Then the exit code is 0

  @gitleaks
  Scenario: The allow file is not itself flagged for its own entries
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I run "leftblock check"
    Then stderr does not contain "Invalid .leftblock-allow.yml"
    And the exit code is 0

  @gitleaks
  Scenario: A missing reason is refused
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings without giving a reason
    Then the exit code is 1
    And stderr contains "at least 10 characters"
    And stderr does not contain "usage:"
    And there is no allow file in the working tree or the index

  @gitleaks
  Scenario Outline: A reason that is too short is refused
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "<reason>"
    Then the exit code is 1
    And stderr contains "at least 10 characters"
    And there is no allow file in the working tree or the index

    Examples:
      | reason      |
      |    short    |
      | too brief   |

  @gitleaks
  Scenario: A reason that repeats the flagged value is refused
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings quoting the flagged address in the reason
    Then the exit code is 1
    And stderr contains "The reason would itself be flagged (rule leftblock-personal-email)"
    And stderr contains "describe it instead"
    And there is no allow file in the working tree or the index

  @gitleaks
  Scenario: A refused reason leaves earlier entries and local edits untouched
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I extend "second.tsx" with a personal address and stage it
    And I note the finding ids from a dry run
    And the allow file gets a local note that is not staged
    And I remember the allow file and what is staged for it
    And I record an override for the noted findings quoting the flagged address in the reason
    Then the exit code is 1
    And the allow file and what is staged for it are as remembered

  @gitleaks
  Scenario: A flagged value inside the allow file has no id and asks for a reworded reason
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And the staged allow file has its reason reworded to quote the flagged address
    And I run "leftblock check"
    Then the exit code is 1
    And no finding is listed with an id
    And stderr contains "A reason in .leftblock-allow.yml contains a flagged value; reword that reason (don't repeat the value)."

  @gitleaks
  Scenario: An entry with an empty reason blocks the commit
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And the staged allow file has its reason emptied by hand
    And I run "leftblock check"
    Then the exit code is 2
    And stderr contains "Invalid .leftblock-allow.yml"

  @gitleaks
  Scenario: An allow file that is not valid YAML blocks even clean content
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    And a staged file ".leftblock-allow.yml" containing:
      """
      version: [
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "Invalid .leftblock-allow.yml"

  @gitleaks
  Scenario: An allow file with an unsupported version blocks even clean content
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    And a staged file ".leftblock-allow.yml" containing:
      """
      version: 2
      allow: []
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "Invalid .leftblock-allow.yml"

  @gitleaks
  Scenario: An entry without an id blocks even clean content
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "app.py" containing a synthetic harmless code
    And a staged file ".leftblock-allow.yml" containing:
      """
      version: 1
      allow:
        - rule: "some-rule"
          file: "some-file"
          reason: "A long enough reason"
      """
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "Invalid .leftblock-allow.yml"

  @gitleaks
  Scenario: An unknown id is refused
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "page.tsx" containing a synthetic personal email
    When I try to record an override for an id that no finding has
    Then the exit code is 1
    And stderr contains "Not a current finding id"
    And there is no allow file in the working tree or the index

  Scenario: A missing scanner is an error that no override can cover
    Given a repository without LeftBlock
    And the configured scanner is not installed
    And a staged file "page.txt" containing a synthetic personal email
    And a staged file ".leftblock-allow.yml" containing:
      """
      version: 1
      allow:
        - id: "0123456789abcdef"
          rule: "x"
          file: "page.txt"
          reason: "A long enough reason."
      """
    When I run "leftblock check"
    Then the exit code is 2
    When I try to record an override for an id that no finding has
    Then the exit code is 1
    And stderr contains "A checker could not complete"

  @gitleaks
  Scenario: The receipt of a commit that used overrides counts them
    Given a repository with LeftBlock installed in receipt mode
    And a staged file "page.tsx" containing a synthetic personal email
    When I commit the staged files
    Then the commit is blocked
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "Public role address for the site"
    And I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspection-result: allowed:1"
    And the latest commit message does not contain "Inspection-result: clean"
