Feature: The model in the commit gate
  As a developer whose secrets do not always have a recognisable shape
  I want the commit gate to ask the Privacy Filter model before the commit exists
  So that what the pattern rules miss is stopped on my machine, at a cost I choose

  The Privacy Filter model (chapter 17) can run inside the gate itself, so
  "leftblock check" and the commit hook both report what it flags, alongside
  gitleaks, in one attempt. It is off unless a person turns it on, and it is
  configured only through Git, so nothing is committed to the repository:
  "git config --global" sets a machine default, a plain "git config" sets one
  repository, and "git -c" covers one commit. leftblock.deep.mode is "off"
  (the default), "resident" or "per-commit". Resident keeps the model in one
  background server per user, reached over a private Unix socket, so only the
  first commit after a restart pays for loading it; per-commit loads the model
  in the hook each time, for machines that cannot spare the memory between
  commits. leftblock.deep.onUnavailable decides what a missing model or a
  server that cannot start means: "block" (the default) refuses the commit with
  no override, "warn" prints a warning and lets the commit continue. An
  invalid setting blocks and names the key; it never falls back silently.
  leftblock.deep.idleMinutes (default 60, 0 never) ends an idle server, and
  leftblock.deep.labels and leftblock.deep.threshold mean what the deep-scan
  options mean. A finding blocks like a gitleaks finding, is overridden the
  same way and its value is never printed. These specs replace the model with
  the stub detector, which runs inside the real server process and socket.

  Background:
    Given the deep scan model is replaced by a stub detector
    And the Privacy Filter server uses a private runtime directory

  # --- Off by default --------------------------------------------------------

  Scenario: Nothing is asked of the model unless a person turns it on
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit succeeds
    And the model was never consulted
    And no Privacy Filter server is running

  Scenario: Mode off is the same as no setting
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "off"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit succeeds
    And the model was never consulted

  # --- Each mode, in each kind of gate -----------------------------------------

  Scenario Outline: A flagged commit is blocked and a clean one passes, in the local gate
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "<mode>"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit is blocked
    And HEAD has not moved
    And stderr contains "privacy-filter-private_phone"
    And the output does not reveal the synthetic value

    Examples:
      | mode       |
      | resident   |
      | per-commit |

  Scenario Outline: A clean commit passes after the model has looked at it
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "<mode>"
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit succeeds
    And the model was consulted

    Examples:
      | mode       |
      | resident   |
      | per-commit |

  Scenario Outline: The receipt hook asks the model too
    Given a repository with LeftBlock installed in receipt mode
    And the repository sets "leftblock.deep.mode" to "<mode>"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "privacy-filter-private_phone"
    And the output does not reveal the synthetic value

    Examples:
      | mode       |
      | resident   |
      | per-commit |

  Scenario: A clean commit in receipt mode is signed
    Given a repository with LeftBlock installed in receipt mode
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit succeeds
    And the latest commit message contains "Inspection-result: clean"

  @gitleaks
  Scenario: The model is asked even when gitleaks has already found something
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "settings.cfg" containing a synthetic session UUID
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "privacy-filter-private_phone"
    And stderr contains "leftblock-session-uuid"

  # --- Overrides ----------------------------------------------------------------

  Scenario: A recorded override lets the commit pass
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "reviewed: a public support line"
    And I commit the staged files
    Then the commit succeeds
    And the commit includes the allow file

  @gitleaks
  Scenario: One override command covers a model finding and a gitleaks finding
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "settings.cfg" containing a synthetic session UUID
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I note the finding ids from a dry run
    And I record an override for the noted findings because "reviewed: both are test fixtures"
    Then the staged allow file records 2 overrides
    And the output does not reveal the synthetic value

  Scenario: The override command printed for a model finding records it
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "per-commit"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I run "leftblock check"
    Then the last line of stderr contains "allow"
    And the last line of stderr contains "--reason"

  Scenario: Recording an override with allow --deep uses the configured server
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And the repository sets "leftblock.deep.threshold" to "0.95"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.96
    When I note the finding ids from a deep scan
    And I note the server process id
    And I record a deep scan override for the noted findings because "reviewed: a public support line"
    Then the exit code is 0
    And the server process id is unchanged

  # --- When the model is not available ---------------------------------------------

  Scenario Outline: A missing model extra blocks by default, with no override
    Given a repository with LeftBlock installed as a local check-only gate
    And the deep scan extra is not installed
    And the repository sets "leftblock.deep.mode" to "<mode>"
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "pip install 'leftblock[deep]'"
    And stderr contains "no override is available"

    Examples:
      | mode       |
      | resident   |
      | per-commit |

  Scenario Outline: A missing model extra only warns when asked to
    Given a repository with LeftBlock installed as a local check-only gate
    And the deep scan extra is not installed
    And the repository sets "leftblock.deep.mode" to "<mode>"
    And the repository sets "leftblock.deep.onUnavailable" to "warn"
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit succeeds
    And stderr contains "Privacy Filter skipped"

    Examples:
      | mode       |
      | resident   |
      | per-commit |

  Scenario: The gate never downloads the model
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And the model weights are not downloaded
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock deep-server download"

  # --- Invalid settings --------------------------------------------------------------

  Scenario Outline: An invalid setting blocks and names the key
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "<key>" to "<value>"
    And a staged file "notes.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "Invalid <key>"
    And the model was never consulted

    Examples:
      | key                          | value   |
      | leftblock.deep.mode          | always  |
      | leftblock.deep.onUnavailable | ignore  |
      | leftblock.deep.idleMinutes   | soon    |
      | leftblock.deep.labels        | nothing |
      | leftblock.deep.threshold     | 1.5     |

  # --- Where the settings come from -----------------------------------------------------

  Scenario: A machine default turns the model on for every repository
    Given a repository with LeftBlock installed as a local check-only gate
    And the global Git config sets "leftblock.deep.mode" to "per-commit"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "privacy-filter-private_phone"

  Scenario: A repository setting beats the machine default
    Given a repository with LeftBlock installed as a local check-only gate
    And the global Git config sets "leftblock.deep.mode" to "per-commit"
    And the repository sets "leftblock.deep.mode" to "off"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit succeeds
    And the model was never consulted

  Scenario: One commit can turn the model on with git -c
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files with "leftblock.deep.mode" set to "per-commit" for that commit
    Then the commit is blocked
    And stderr contains "privacy-filter-private_phone"

  Scenario: One commit can turn the model off with git -c
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "per-commit"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files with "leftblock.deep.mode" set to "off" for that commit
    Then the commit succeeds
    And the model was never consulted

  Scenario: The configured labels decide what is reported
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "per-commit"
    And the repository sets "leftblock.deep.labels" to "private_person"
    And a staged file "owner.cfg" containing a person name that the model flags as private_person at 0.99
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "privacy-filter-private_person"

  Scenario: The configured threshold decides what is reported
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "per-commit"
    And the repository sets "leftblock.deep.threshold" to "0.995"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit succeeds

  # --- The resident server ----------------------------------------------------------------

  Scenario: The second commit reuses the running server
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    And I note the server process id
    And I stage another harmless file "two.txt"
    And I commit the staged files
    Then the commit succeeds
    And the server process id is unchanged

  Scenario: Commits that start at the same time share one new server
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When 4 copies of the repository check their staged changes at the same time
    Then every check exits with 0
    And exactly one Privacy Filter server was started

  Scenario: A server that sees no commits for a while exits and removes its socket
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And the repository sets "leftblock.deep.idleMinutes" to "0.03"
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit succeeds
    And within 20 seconds no Privacy Filter server is running
    And the server socket is gone

  Scenario: The next commit after an idle exit starts a new server
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And the repository sets "leftblock.deep.idleMinutes" to "0.03"
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    And within 20 seconds no Privacy Filter server is running
    And I stage another harmless file "two.txt"
    And I commit the staged files
    Then the commit succeeds

  Scenario: The server can be inspected and stopped
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    And I run "leftblock deep-server status"
    Then the exit code is 0
    And stderr contains "Privacy Filter server running"
    When I run "leftblock deep-server stop"
    Then the exit code is 0
    And no Privacy Filter server is running

  # --- Privacy of the socket ---------------------------------------------------------------

  Scenario: The socket and its directory are private to the owner
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the server directory is accessible only by its owner
    And the server socket is accessible only by its owner

  Scenario: A server directory open to other users is refused
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And the server directory is open to other users
    And a staged file "one.txt" containing:
      """
      Nothing sensitive here.
      """
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "closed to others"
    And the server socket is gone

  Scenario: The server never logs what it was asked about
    Given a repository with LeftBlock installed as a local check-only gate
    And the repository sets "leftblock.deep.mode" to "resident"
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit is blocked
    And the server log records that the server started and was ready
    And the server log contains no staged text

  # --- Merges --------------------------------------------------------------------------------

  @gitleaks
  Scenario: A merge does not ask the model about content it merely inherits
    Given a repository with LeftBlock installed as a local check-only gate
    And the history is on a branch called "trunk"
    And the file "base.txt" is committed
    And the repository sets "leftblock.deep.mode" to "resident"
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "inherited.cfg" containing a synthetic phone number
    And the model is told to flag the synthetic values so far as private_phone at 0.99
    And the branch "feature" is checked out
    And a merge of "trunk" is in progress, not yet committed
    When I commit the staged files
    Then the commit succeeds
    And the model was never consulted

  @gitleaks
  Scenario: A merge still asks the model about what the merge itself adds
    Given a repository with LeftBlock installed as a local check-only gate
    And the history is on a branch called "trunk"
    And the file "base.txt" is committed
    And the repository sets "leftblock.deep.mode" to "resident"
    And a branch "feature" is created from the current one and checked out
    And the current branch gains a commit adding "feature.txt" containing a synthetic harmless code
    And the branch "trunk" is checked out
    And the current branch gains a commit adding "trunk.txt" containing a synthetic harmless code
    And the branch "feature" is checked out
    And a merge of "trunk" is in progress, not yet committed
    And a staged file "contacts.cfg" containing a phone number that the model flags as private_phone at 0.99
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "privacy-filter-private_phone"
