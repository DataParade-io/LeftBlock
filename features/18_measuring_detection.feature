Feature: Measuring detection
  As a maintainer who has to say how much LeftBlock really catches
  I want a repeatable evaluation of the scanners against labelled data
  So that claims about coverage come with counts, intervals and a stated tier of what matters most

  The evaluation harness in "eval/" (not part of the package, never run by CI
  beyond these specs) scores four detectors on labelled lines: stock gitleaks,
  gitleaks with LeftBlock's shipped ruleset, the deep scan, and the last two
  combined. A detector hits a labelled line when one of its findings overlaps
  that line. Lines labelled true (T) and false (F) are scored; lines labelled
  X (undecided) are excluded and counted. Recall and precision come with
  Wilson 95% intervals, overall and for a critical tier of credential
  categories (cloud keys, private keys, provider tokens, passwords, auth
  headers and JWTs). The deep scan is slow, so it reads context windows around
  a sample of labelled lines, and always every critical-tier true line. A
  report holds counts, rates and category names only. These specs build a tiny
  CredData-shaped dataset at run time and replace the model with a stub.

  # --- Scoring -------------------------------------------------------------------

  @gitleaks
  Scenario: Recall and precision are counted over labelled lines
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category   | shape            |
      | T     | Slack Token | ruleset key      |
      | T     | Slack Token | ruleset key      |
      | T     | Password   | quiet value      |
      | F     | Password   | quiet value      |
      | F     | UUID       | uuid             |
    When I evaluate the fixture with detectors "stock,leftblock"
    Then the evaluation succeeds
    And in the full files "LeftBlock ruleset" scores 2 true positives, 1 false positives and 1 misses
    And in the full files "LeftBlock ruleset" has recall 66.7% and precision 66.7%
    And in the full files "stock gitleaks" scores 0 true positives, 0 false positives and 3 misses

  @gitleaks
  Scenario: Every rate carries a 95% interval
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
      | T     | Password    | quiet value |
      | F     | Password    | quiet value |
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And every reported rate has a 95% interval around it

  @gitleaks
  Scenario: A multi-line label is one unit, hit when a finding overlaps any of its lines
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category        | shape     |
      | T     | PEM Private Key | pem block |
      | T     | Password        | quiet value |
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And in the full files "LeftBlock ruleset" scores 1 true positives, 0 false positives and 1 misses

  # --- The critical tier ------------------------------------------------------------

  @gitleaks
  Scenario: Missed passwords count against the critical tier and missed salts do not
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape       |
      | T     | Password | quiet value |
      | T     | Salt     | quiet value |
      | T     | Salt     | quiet value |
      | T     | PEM Private Key | pem block |
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And in the full files the critical tier holds 2 true lines and "LeftBlock ruleset" misses 1 of them
    And in the full files "LeftBlock ruleset" scores 1 true positives, 0 false positives and 3 misses

  @gitleaks
  Scenario: Generic key categories are outside the critical tier
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape       |
      | T     | Key      | quiet value |
      | T     | Secret   | quiet value |
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And in the full files the critical tier holds 0 true lines and "LeftBlock ruleset" misses 0 of them

  # --- Lines labelled X -------------------------------------------------------------

  @gitleaks
  Scenario: Lines labelled X are excluded and counted
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
      | X     | Other       | ruleset key |
      | X     | Other       | quiet value |
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And 2 labelled lines are excluded as X
    And in the full files "LeftBlock ruleset" scores 1 true positives, 0 false positives and 0 misses

  # --- Lines nobody labelled ----------------------------------------------------------

  @gitleaks
  Scenario: Flags on unlabelled lines are reported apart from the scores
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
      | F     | Password    | quiet value |
    And the fixture also holds an unlabelled file with a ruleset key
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And 1 findings on unlabelled lines are reported for "LeftBlock ruleset" apart from the scores
    And in the full files "LeftBlock ruleset" scores 1 true positives, 0 false positives and 0 misses

  # --- The deep scan and combining detectors --------------------------------------------

  @gitleaks
  Scenario: The deep scan finds what the rules miss and the combination finds both
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape             |
      | T     | Slack Token | ruleset key       |
      | T     | Password    | model-only secret |
    And the model flags the fixture's model-only secrets as secret at 0.97
    When I evaluate the fixture with detectors "stock,leftblock,deep,combined"
    Then the evaluation succeeds
    And in the deep sample "LeftBlock ruleset" has recall 50.0% and precision 100.0%
    And in the deep sample "deep scan" has recall 50.0% and precision 100.0%
    And in the deep sample "combined" has recall 100.0% and precision 100.0%
    And the deep scan adds 1 true positives and 0 false positives over the LeftBlock ruleset

  @gitleaks
  Scenario: The deep scan's extra false positives are counted
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape             |
      | T     | Password | model-only secret |
      | F     | Password | model-only secret |
    And the model flags the fixture's model-only secrets as secret at 0.97
    When I evaluate the fixture with detectors "leftblock,deep,combined"
    Then the evaluation succeeds
    And in the deep sample "deep scan" has recall 100.0% and precision 50.0%
    And the deep scan adds 1 true positives and 1 false positives over the LeftBlock ruleset

  @gitleaks
  Scenario: Every critical-tier true line is read by the model whatever the sample size
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape             |
      | T     | Password | model-only secret |
      | T     | Password | model-only secret |
      | F     | Salt     | quiet value       |
      | F     | Salt     | quiet value       |
      | F     | Salt     | quiet value       |
      | F     | Salt     | quiet value       |
      | F     | Salt     | quiet value       |
    And the model flags the fixture's model-only secrets as secret at 0.97
    When I evaluate the fixture with detectors "deep" and a deep sample of 0
    Then the evaluation succeeds
    And in the deep sample "deep scan" scores 2 true positives, 0 false positives and 0 misses
    And the deep sample holds 2 critical true lines

  @gitleaks
  Scenario: Sampled lines are weighted back to the population
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape       |
      | F     | Salt     | quiet value |
      | F     | Salt     | quiet value |
      | F     | Salt     | quiet value |
      | F     | Salt     | quiet value |
      | F     | Salt     | quiet value |
      | F     | Salt     | quiet value |
    When I evaluate the fixture with detectors "leftblock,deep" and a deep sample of 0
    Then the evaluation succeeds
    And the deep sample estimates 6 false lines from 3 sampled

  # --- Reports -----------------------------------------------------------------------------

  @gitleaks
  Scenario: The reports contain no value and no file path
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category        | shape             |
      | T     | Slack Token     | ruleset key       |
      | T     | Password        | model-only secret |
      | T     | PEM Private Key | pem block         |
      | F     | UUID            | uuid              |
    And the model flags the fixture's model-only secrets as secret at 0.97
    When I evaluate the fixture with detectors "stock,leftblock,deep,combined"
    Then the evaluation succeeds
    And the report reveals no fixture value or file path
    And the report states the critical tier and the excluded count

  @gitleaks
  Scenario: The generated corpus is built at run time and leaves nothing behind
    Given a fixture dataset
    When I evaluate the generated corpus with detectors "stock,leftblock"
    Then the evaluation succeeds
    And the generated corpus had more than 300 labelled lines
    And the generated corpus left no files behind
    And the report reveals no generated value

  # --- Where the data may live ---------------------------------------------------------------

  Scenario: A data directory inside a Git repository is refused
    Given a repository without LeftBlock
    When I evaluate with the data directory inside that repository
    Then the exit code is 2
    And stderr contains "inside a Git repository"

  # --- Running it from a fresh clone -------------------------------------------------------------

  Scenario: A missing gitleaks is reported with the command that installs the pinned one
    Given a fixture dataset
    And gitleaks is not installed
    When I check the evaluation prerequisites without the deep scan
    Then the exit code is 2
    And stderr contains "gitleaks is not installed"
    And stderr contains "releases/download/v8.30.1"

  Scenario: A missing deep-scan extra is reported with the command that installs it
    Given a fixture dataset
    And gitleaks at the pinned version
    And the deep scan extra is not installed
    When I check the evaluation prerequisites with the deep scan
    Then the exit code is 2
    And stderr contains "transformers and torch"
    And stderr contains "eval/requirements.txt"

  Scenario: With everything in place the check says so
    Given a fixture dataset
    And gitleaks at the pinned version
    When I check the evaluation prerequisites without the deep scan
    Then the exit code is 0
    And stdout contains "All prerequisites are in place"

  @gitleaks
  Scenario: Another gitleaks version is refused
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
    And gitleaks reporting version 8.0.0
    When I evaluate the fixture with detectors "leftblock" and no mismatch allowance
    Then the exit code is 2
    And stderr contains "pins 8.30.1"
    And no results were written

  @gitleaks
  Scenario: Another gitleaks version can be allowed, loudly, and the results say so
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
    And gitleaks reporting version 8.0.0
    When I evaluate the fixture with detectors "leftblock"
    Then the evaluation succeeds
    And stdout contains "WARNING: gitleaks 8.0.0 is installed but the evaluation pins 8.30.1"
    And the results record gitleaks 8.0.0 as not matching the pin

  @gitleaks
  Scenario: Every input that can change the numbers is recorded
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape             |
      | T     | Slack Token | ruleset key       |
      | T     | Password    | model-only secret |
    And the model flags the fixture's model-only secrets as secret at 0.97
    When I evaluate the fixture with detectors "stock,leftblock,deep,combined"
    Then the evaluation succeeds
    And the results record the gitleaks version and the pinned one
    And the results record the CredData commit and digests of its labels and files
    And the results record the tier definition and the ruleset digests
    And the results record the seed and the deep sample size
    And the results record the deep-scan model at its pinned revision
    And the report lists these inputs in a provenance section

  @gitleaks
  Scenario: One command checks, fetches, runs and writes the results
    Given a fixture dataset
    When I reproduce the evaluation without the deep scan
    Then the exit code is 0
    And the reproduced results hold both datasets
    And stdout contains "python -m eval compare"

  @gitleaks
  Scenario: Nothing starts when a prerequisite is missing
    Given a fixture dataset
    And gitleaks is not installed
    When I reproduce the evaluation without the deep scan
    Then the exit code is 2
    And stderr contains "nothing was done"
    And no results were written

  Scenario: A data directory left by an interrupted download is not trusted
    Given a fixture dataset
    And the fixture download did not finish
    When I reproduce the evaluation without the deep scan
    Then the exit code is 2
    And stderr contains "did not finish"

  @gitleaks
  Scenario: A smoke run reads only a few files with the model and says it is not an estimate
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape             |
      | T     | Password | model-only secret |
      | T     | Password | model-only secret |
      | T     | Password | model-only secret |
    And the model flags the fixture's model-only secrets as secret at 0.97
    When I reproduce the evaluation with a deep smoke run on 2 files
    Then the exit code is 0
    And the reproduced deep sample reads 2 files and is marked as a smoke run
    And the reproduced generated corpus is scored without the deep scan

  @gitleaks
  Scenario: An interrupted deep scan resumes without reading the finished files again
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category | shape             |
      | T     | Password | model-only secret |
      | T     | Password | model-only secret |
      | T     | Password | model-only secret |
      | T     | Password | model-only secret |
    And the model flags the fixture's model-only secrets as secret at 0.97
    And the model is interrupted after 2 calls
    When I reproduce the evaluation with a deep smoke run on 4 files
    Then the exit code is not 0
    When the interruption is over and I reproduce again
    Then the exit code is 0
    And the model was consulted for 2 more calls
    And the reproduced deep scan scores 4 true positives

  # --- Comparing two results files -----------------------------------------------------------------

  @gitleaks
  Scenario: Comparing a results file with itself shows nothing moved
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
    When I evaluate the fixture with detectors "stock,leftblock"
    And I compare the results with themselves
    Then the exit code is 0
    And stdout contains "0 of"
    And stdout contains "None: same pins"

  @gitleaks
  Scenario: Comparing shows which numbers and inputs moved and never fails on them
    Given a fixture dataset
    And the fixture labels these lines:
      | truth | category    | shape       |
      | T     | Slack Token | ruleset key |
    When I evaluate the fixture with detectors "stock,leftblock"
    And I compare the results with a copy whose LeftBlock recall and gitleaks version are changed
    Then the exit code is 0
    And stdout contains "12.3%"
    And stdout contains "gitleaks.version"

  Scenario: Comparing needs two readable files
    Given a fixture dataset
    When I compare two results files that do not exist
    Then the exit code is 2
    And stderr contains "Cannot read a results file"
