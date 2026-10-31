Feature: The command line
  As a person typing leftblock at a prompt, or a script calling it
  I want a small, predictable command surface with real help
  So that I can discover what exists, trust what a command will do, and install or remove LeftBlock without side effects

  LeftBlock has nine public commands: install, check, allow, deep-scan, scan,
  ci, hook, verify and approve. Each answers --help, the installed "leftblock" command is the
  same program as "python -m leftblock.cli", "--version" names the release,
  and mistakes in the command line exit with status 2 and a usage message.
  Running "check" with the default policy never creates signing credentials.
  The package installs one command and one Python package, upgrading or
  removing it leaves other packages alone, and receipts already stamped with
  an older validator name keep verifying.

  # --- Help and discovery ----------------------------------------------------

  Scenario: The top-level help describes LeftBlock and lists every command
    When I run "leftblock --help"
    Then the exit code is 0
    And stdout contains "usage:"
    And stdout contains "LeftBlock"
    And stdout contains "install"
    And stdout contains "check"
    And stdout contains "allow"
    And stdout contains "deep-scan"
    And stdout contains "scan"
    And stdout contains "ci"
    And stdout contains "hook"
    And stdout contains "verify"
    And stdout contains "approve"

  Scenario Outline: Every public command has its own help
    When I run "leftblock <command> --help"
    Then the exit code is 0
    And stdout contains "usage:"
    And stdout contains "<command>"

    Examples:
      | command |
      | install |
      | check   |
      | allow   |
      | deep-scan |
      | scan    |
      | ci      |
      | hook    |
      | verify  |
      | approve |

  Scenario: The help for check names the default policy file
    When I run "leftblock check --help"
    Then stdout contains ".leftblock.yml"

  Scenario Outline: The installed leftblock command dispatches each command
    When I run the installed leftblock command with "<command> --help"
    Then the exit code is 0
    And stdout contains "usage: leftblock <command>"

    Examples:
      | command |
      | install |
      | check   |
      | allow   |
      | deep-scan |
      | scan    |
      | hook    |
      | verify  |
      | approve |

  Scenario: The version is printed
    When I run the installed leftblock command with "--version"
    Then the exit code is 0
    And stdout reports a leftblock version number

  Scenario: The module entry point reports the version too
    When I run "leftblock --version"
    Then the exit code is 0
    And stdout reports a leftblock version number

  # --- Mistakes on the command line -----------------------------------------

  Scenario: A missing command is a usage error
    When I run leftblock without any command
    Then the exit code is 2
    And stderr contains "usage:"
    And stderr contains "required: command"

  Scenario: An unknown command is a usage error
    When I run "leftblock frobnicate"
    Then the exit code is 2
    And stderr contains "invalid choice"

  Scenario: A missing argument is a usage error
    When I run "leftblock approve"
    Then the exit code is 2
    And stderr contains "usage:"

  Scenario: An unknown option is a usage error
    When I run "leftblock check --no-such-option"
    Then the exit code is 2
    And stderr contains "unrecognized arguments"

  # --- The default policy ------------------------------------------------------

  Scenario: Checking with the default policy creates no signing credentials
    Given a repository without LeftBlock
    And the repository has a checker policy ".leftblock.yml" that always passes
    And a record of the policy file and the signing secret location
    When I run "leftblock check"
    Then the exit code is 0
    And no signing credentials were created
    And the policy file is exactly as it was

  # --- Receipts keep verifying -------------------------------------------------

  Scenario Outline: Receipts stamped with an earlier validator name still verify
    Given a repository with LeftBlock installed in receipt mode
    And a commit whose receipt names the validator "<validator>" and was signed for "<validator>"
    When I run "leftblock verify HEAD"
    Then the exit code is 0
    And stdout contains "verified"

    Examples:
      | validator                |
      | historical-inspector-v0  |
      | leftblock-v1             |

  Scenario: Renaming the validator in a stored receipt invalidates it
    Given a repository with LeftBlock installed in receipt mode
    And a commit whose receipt names the validator "leftblock-v1" and was signed for "historical-inspector-v0"
    When I run "leftblock verify HEAD"
    Then the exit code is 1
    And stderr contains "No valid signature"

  # --- What the distribution installs ----------------------------------------

  Scenario: The distribution is leftblock and nothing else is named after it
    Given a wheel built offline from the project sources
    Then the distribution is named leftblock at the project's version, with its license
    And the distribution installs one command, "leftblock", running "leftblock.cli:main"

  Scenario: The distribution ships only the package and its metadata
    Given a wheel built offline from the project sources
    Then the distribution contains the implementation modules and the shipped rules
    And the distribution contains only the leftblock package and its own metadata
    And the bundled rules and license are identical to the project's

  Scenario: Upgrading and reinstalling leave other packages alone
    Given an isolated environment holding an independent package and an older LeftBlock
    When I upgrade LeftBlock from the built wheel
    Then the leftblock command is the new release
    And the independent package is exactly as it was
    When I force-reinstall LeftBlock from the built wheel
    Then the leftblock command is the new release
    And the independent package is exactly as it was

  Scenario: Uninstalling LeftBlock leaves other packages alone
    Given an isolated environment holding an independent package and an older LeftBlock
    When I upgrade LeftBlock from the built wheel
    And I uninstall LeftBlock
    Then the leftblock command is gone
    And the independent package's command still works
    And the independent package is exactly as it was

  Scenario: Uninstalling another package leaves LeftBlock alone
    Given an isolated environment holding an independent package and an older LeftBlock
    When I upgrade LeftBlock from the built wheel
    And I uninstall the independent package
    Then the independent package's command is gone
    And the leftblock command is the new release
