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
