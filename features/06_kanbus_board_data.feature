@gitleaks
Feature: Kanbus board data
  As a developer who tracks work with Kanbus
  I want the identifiers Kanbus writes into its board files to pass the gate
  So that an ordinary kbs write never blocks a commit, while real secrets and personal data in those files are still caught

  Kanbus is the task tracker in these repositories, and its issue, event and
  cache files are full of identifiers: session ids, actor ids and UUIDs in
  any field or prose. They are not sensitive, so in board data (project issue
  files, project event files including the .jsonl usage log, and the derived
  project cache index) the session UUID and actor id rules stay quiet. The
  exception is narrow. The same content anywhere else is still flagged;
  personal emails, home paths and keys inside board files are still flagged;
  AWS account and resource ids are flagged in board files as well, in comment
  and description text and in event payloads; and the top-level project_id line of .kanbus.yml is accepted only as a
  version 4 UUID. When a board file does block, the hint says to fix it
  through kbs rather than by hand, and for append-only event files says how.

  Scenario Outline: Identifiers in every shape pass in an issue file
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "project/issues/PPY-x.json" containing a synthetic <shape>
    When I commit the staged files
    Then the commit succeeds

    Examples:
      | shape                                      |
      | board document with session-style fields   |
      | board document with a prefixed session value |
      | board document with UUIDs in prose         |
      | board document with a nested actor id      |
      | board document with a split actor id       |
      | board document with a plain user name as actor id |
      | minified board event                       |

  Scenario Outline: Identifiers pass in every kind of board path
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic <shape>
    When I commit the staged files
    Then the commit succeeds

    Examples:
      | path                                              | shape                                    |
      | project/issues/PPY-x.json                         | board document with session-style fields |
      | project/events/2026-10-20T00-00-00.000Z__x.json   | board document with session-style fields |
      | project/events/llm_usage.jsonl                    | minified board event                     |
      | project/.cache/index.json                         | board document with UUIDs in prose       |
      | sub/dir/project/issues/PPY-x.json                 | board document with a nested actor id    |
      | sub/dir/project/events/e.json                     | minified board event                     |
      | sub/dir/project/.cache/index.json                 | board document with a split actor id     |
      | project/events/2026-10-20T00-00-00.000Z__x.json   | board document with a nested actor id    |
      | project/events/e.json                             | board document with a prefixed session value |
      | project/.cache/index.json                         | board document with a plain user name as actor id |

  Scenario Outline: The same identifiers are still flagged outside board paths
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic board document with session-style fields
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-session-uuid"
    And the output does not reveal the synthetic value

    Examples:
      | path                        |
      | notes.md                    |
      | project/other.json          |
      | project/issues/sub/x.json   |
      | project/events/sub/x.json   |
      | project/events.json         |
      | project/issues/x.json.bak   |
      | project/issues/x.jsonl      |
      | src/project/issues-like/x.json |
      | myproject/issues/x.json     |
      | project/.cache/other.json   |
      | project/.cache/sub/index.json |

  Scenario Outline: Every identifier shape is flagged in an ordinary file
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.md" containing a synthetic <shape>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value

    Examples:
      | shape                                             | rule                     |
      | board document with a prefixed session value      | leftblock-session-uuid   |
      | board document with UUIDs in prose                | leftblock-session-uuid   |
      | board document with a nested actor id             | leftblock-session-uuid   |
      | board document with a split actor id              | leftblock-session-uuid   |
      | minified board event                              | leftblock-session-uuid   |
      | board document with a plain user name as actor id | leftblock-actor-id       |

  Scenario Outline: A plain actor id is flagged outside board paths
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic board document with a plain user name as actor id
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-actor-id"
    And the output does not reveal the synthetic value

    Examples:
      | path                |
      | notes.json          |
      | project/events.json |
      | project/other.json  |
      | myproject/issues/x.json |

  Scenario Outline: Personal data and keys are still flagged inside board files
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic <shape>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value

    Examples:
      | path                                            | shape                                       | rule                      |
      | project/issues/PPY-x.json                       | board document with a personal email        | leftblock-personal-email  |
      | project/issues/PPY-x.json                       | board document with a home path             | leftblock-home-path-posix |
      | project/issues/PPY-x.json                       | board document with an OpenAI key           | leftblock-openai-key      |
      | project/issues/PPY-x.json                       | board document with an OpenAI key as actor id | leftblock-openai-key    |
      | project/events/2026-10-20T00-00-00.000Z__x.json | board document with a personal email        | leftblock-personal-email  |
      | project/events/llm_usage.jsonl                  | board document with a home path             | leftblock-home-path-posix |
      | project/.cache/index.json                       | board document with an OpenAI key           | leftblock-openai-key      |
      | sub/dir/project/issues/PPY-x.json               | board document with a personal email        | leftblock-personal-email  |

  Scenario Outline: AWS ids and personal emails in event and issue text are blocked
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic <shape>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value

    Examples:
      | path                                            | shape                                                 | rule                      |
      | project/events/2026-10-20T00-00-00.000Z__x.json | board event with an AWS account id in a comment       | leftblock-aws-account-id  |
      | project/events/2026-10-20T00-00-00.000Z__x.json | board event with a personal email in a comment        | leftblock-personal-email  |
      | project/events/llm_usage.jsonl                  | board event with an AWS account id in a comment       | leftblock-aws-account-id  |
      | project/issues/PPY-x.json                       | board event with an AWS account id in a comment       | leftblock-aws-account-id  |
      | project/issues/PPY-x.json                       | board issue with an AWS resource id in its description | leftblock-aws-resource-id |
      | project/events/e.json                           | board issue with an AWS resource id in its description | leftblock-aws-resource-id |
      | sub/dir/project/events/e.json                   | board event with an AWS account id in a comment       | leftblock-aws-account-id  |
      | project/.cache/index.json                       | board issue with an AWS resource id in its description | leftblock-aws-resource-id |

  Scenario Outline: The project id in .kanbus.yml is accepted only as a top-level version 4 UUID
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic <content>
    When I commit the staged files
    Then the commit succeeds

    Examples:
      | path             | content                |
      | .kanbus.yml      | Kanbus project id line |
      | sub/.kanbus.yml  | Kanbus project id line |

  Scenario Outline: Any other project id or UUID in Kanbus configuration is flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "<path>" containing a synthetic <content>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-session-uuid"
    And the output does not reveal the synthetic value

    Examples:
      | path        | content                                | situation                    |
      | .kanbus.yml | indented Kanbus project id             | the key is nested            |
      | .kanbus.yml | Kanbus session id line                 | a different key              |
      | .kanbus.yml | Kanbus project id with a version 1 UUID | the UUID is not version 4   |
      | config.yml  | Kanbus project id line                 | a different file             |

  Scenario: A realistic board of issues, events and a project id commits through the hook
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged Kanbus board with an issue, an event and a project id
    When I commit the staged files
    Then the commit succeeds

  Scenario: Board files saved with Windows line endings commit through the hook
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged Kanbus event and cache index saved with Windows line endings
    When I commit the staged files
    Then the commit succeeds

  Scenario: A home path inside an issue still blocks the commit and points at kbs
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged Kanbus board whose issue description mentions a synthetic home path
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr names the staged Kanbus issue file
    And stderr contains "leftblock-home-path-posix"
    And stderr contains "Hint: Use a relative path, $HOME or ~ instead."
    And stderr contains "This issue file is written by Kanbus; fix the content with kbs update"
    And the output does not reveal the synthetic value

  Scenario: A flagged event file says it is append-only history and how to recover
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "project/events/2026-10-20T10-00-00.000Z__x.json" containing a synthetic board document with a home path
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "append-only history"
    And stderr contains "kbs delete <issue id>"
    And stderr does not contain "kbs update"

  Scenario: The Kanbus hint appears once per file however many findings the file has
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "project/issues/PPY-a.json" containing a synthetic board document with two home paths
    When I run "leftblock check"
    Then the exit code is 1
    And stderr shows "project/issues/PPY-a.json: This issue file is written by Kanbus" 1 time

  Scenario: Each flagged board file gets its own Kanbus hint
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "project/issues/PPY-a.json" containing a synthetic board document with a home path
    And a staged file "project/issues/PPY-b.json" containing a synthetic board document with a home path
    When I run "leftblock check"
    Then the exit code is 1
    And stderr shows "This issue file is written by Kanbus" 2 times

  Scenario: A flagged file outside the board gets no Kanbus hint
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.md" containing a synthetic home path
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "Hint: Use a relative path"
    And stderr does not contain "written by Kanbus"
    And stderr does not contain "append-only"
