Feature: Scanning text outside git
  As the author of a tool that handles text which may hold secrets or personal data
  I want to run LeftBlock's rules over text that is not in a Git repository
  So that I can find and redact sensitive spans without staging anything or writing my own detectors

  "leftblock scan" applies the shipped ruleset and the same post-filters as
  the commit hook (the Bitcoin WIF checksum, for one) to text that has no
  Git behind it. It reads in one of two ways. With --jsonl it takes records
  from standard input, one JSON object per line holding an opaque "id" and
  the "text", and prints one JSON object per finding with the record id, the
  rule, its kind (secret, personal, crypto or deep), the finding id, and the
  start and end as UTF-8 byte offsets into that record's text, so a caller
  can cut the span out. With paths it scans files and directories and prints
  text or JSON, with byte offsets into each file and the line. Either way the
  matched value is never printed. Gitleaks runs once over a private
  temporary copy of all the records, which is removed afterwards, even on an
  error; no value ever travels in an argument list. Recorded overrides belong
  to a repository's commits and are not applied. The optional --deep adds the
  Privacy Filter model with the deep scan's defaults; these specs replace the
  model with a stub detector. Exit status is 0 for no findings, 1 for
  findings and 2 for an error.

  # --- Records in, findings out ------------------------------------------------

  @gitleaks
  Scenario: A record with sensitive text yields one finding line, and a clean record none
    Given a record "turn-1" with the text "please mail [email] about the release"
    And a record "turn-2" with the text "nothing sensitive in this one"
    When I scan the records
    Then the exit code is 1
    And the scan reports 1 finding
    And finding 1 of record "turn-1" is for rule "leftblock-personal-email" of kind "personal"
    And finding 1 of record "turn-1" slices to [email]
    And every finding has exactly the fields "id, start, end, rule, kind, finding_id"
    And stdout holds nothing but one JSON object per line
    And the scan finding id is 16 hexadecimal digits

  @gitleaks
  Scenario: Records with nothing sensitive pass
    Given a record "turn-1" with the text "an ordinary line"
    When I scan the records
    Then the exit code is 0
    And the scan reports 0 findings
    And stdout does not contain "{"

  @gitleaks
  Scenario Outline: Each kind of finding is named by rule and category
    Given a record "r" with the text "<text>"
    When I scan the records
    Then the exit code is 1
    And finding 1 of record "r" is for rule "<rule>" of kind "<kind>"
    And finding 1 of record "r" slices to [<value>]

    Examples:
      | text                               | value      | rule                     | kind     |
      | contact [email]                    | email      | leftblock-personal-email | personal |
      | client_credential = "[openai key]" | openai key | leftblock-openai-key     | secret   |
      | wallet_import = [wif]              | wif        | leftblock-wif-key        | crypto   |

  # --- Byte offsets ---------------------------------------------------------------

  @gitleaks
  Scenario: Offsets count UTF-8 bytes, not characters
    Given a record "unicode" with the text "héllo 日本 😀 write to [email] soon"
    When I scan the records
    Then finding 1 of record "unicode" starts at byte 28
    And finding 1 of record "unicode" slices to [email]

  @gitleaks
  Scenario: Records may span lines and every line is placed correctly
    Given a record "lines" with the text:
      """
      first line, ünïcode and all
      second line

        third line: [email]
      [email 2] closes the record
      """
    When I scan the records
    Then the scan reports 2 findings
    And finding 1 of record "lines" slices to [email]
    And finding 2 of record "lines" slices to [email 2]
    And finding 1 of record "lines" starts at byte 57

  @gitleaks
  Scenario: Gitleaks reports columns one too far right on every line after the first, and that is corrected
    Given a record "first" with the text "see [email]"
    And a record "later" with the text "one\ntwo\nthree [email]"
    When I scan the records
    Then finding 1 of record "first" slices to [email]
    And finding 1 of record "later" slices to [email]

  @gitleaks
  Scenario: Carriage returns are ordinary characters
    Given a record "crlf" with the text "line one\r\nline two [email]\r\n"
    When I scan the records
    Then finding 1 of record "crlf" slices to [email]

  @gitleaks
  Scenario: A finding that spans several lines is cut at its true ends
    Given a record "key" with the text "before ünï\n  holder [pem] after\nlast"
    When I scan the records
    Then the scan reports 1 finding
    And finding 1 of record "key" is for rule "private-key" of kind "secret"
    And finding 1 of record "key" slices to [pem]

  # --- Post-filters and finding ids -------------------------------------------------

  @gitleaks
  Scenario: The WIF checksum filter applies, so a key-shaped string that fails it is not reported
    Given a record "valid" with the text "wallet_import = [wif]"
    And a record "invalid" with the text "wallet_import = [bad wif]"
    When I scan the records
    Then the scan reports 1 finding
    And finding 1 of record "valid" is for rule "leftblock-wif-key" of kind "crypto"
    And finding 1 of record "valid" slices to [wif]

  @gitleaks
  Scenario: The same value in the same record has one id, and in another record another id
    Given a record "one" with the text "[email] and again [email]"
    And a record "two" with the text "[email]"
    When I scan the records
    Then every finding in record "one" has the same id
    And the ids of the findings in records "one" and "two" differ

  @gitleaks
  Scenario: A finding id is the one the commit hook gives for the same value in a file of that name
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.txt" with the text:
      """
      owner contact: [email]
      """
    When I note the finding id from a check
    And I scan a record "notes.txt" holding the text of the staged file "notes.txt"
    Then the scan finding id equals the id the check gave

  @gitleaks
  Scenario: Recorded overrides are not applied when scanning
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.txt" with the text:
      """
      owner contact: [email]
      """
    When I note the finding id from a check
    And I record an override for the noted finding because "a reviewed false alarm in the notes"
    And I run "leftblock check"
    Then the exit code is 0
    When I scan a record "notes.txt" holding the text of the staged file "notes.txt"
    Then the exit code is 1
    And the scan reports 1 finding

  # --- Bad and empty input -------------------------------------------------------------

  @gitleaks
  Scenario: Empty input is clean
    When I scan empty input
    Then the exit code is 0
    And nothing is printed on stdout

  @gitleaks
  Scenario: A malformed line is an error that names the line and never quotes it
    When I scan the raw input:
      """
      {"id": "ok", "text": "fine"}
      {"id": "broken", "text": "[email]
      """
    Then the exit code is 2
    And stderr contains "Line 2"
    And nothing is printed on stdout
    And the output does not reveal the synthetic value

  @gitleaks
  Scenario: A record without an id or text is an error that names the line
    When I scan the raw input:
      """
      {"id": "ok", "text": "fine"}
      {"id": "ok", "text": "fine"}
      {"id": "no text here"}
      """
    Then the exit code is 2
    And stderr contains "Line 3"
    And nothing is printed on stdout

  @gitleaks
  Scenario: Without gitleaks the scan fails closed
    Given a record "r" with the text "nothing here"
    And gitleaks is not installed
    When I scan the records
    Then the exit code is 2
    And stderr contains "Gitleaks is required"

  # --- Never the value --------------------------------------------------------------------

  @gitleaks
  Scenario: No value is ever printed, in records or in paths
    Given a record "a" with the text "contact [email], key [openai key], wallet_import = [wif]"
    And a file "notes/log.txt" with the text:
      """
      contact [email], key [openai key], wallet_import = [wif]
      """
    When I scan the records
    Then the scan reports 3 findings
    And the output does not reveal the synthetic value
    When I run "leftblock scan notes"
    Then the exit code is 1
    And the output does not reveal the synthetic value
    When I run "leftblock scan --format json notes"
    Then the exit code is 1
    And the output does not reveal the synthetic value

  # --- Temporary files -----------------------------------------------------------------------

  @gitleaks
  Scenario: The records are held in a folder only the owner can enter, and one gitleaks run covers them all
    Given gitleaks calls are recorded
    And 300 clean records and then a record "last" with the text "[email]"
    When I scan the records
    Then the exit code is 1
    And finding 1 of record "last" slices to [email]
    And gitleaks ran once
    And gitleaks was given 301 record files in a folder only the owner can enter
    And no gitleaks argument holds any record text or value

  @gitleaks
  Scenario: The temporary copy is removed after a scan, whether or not it finds anything
    Given the temporary directory is a folder of the scenario
    And a record "r" with the text "contact [email]"
    When I scan the records
    Then the exit code is 1
    And the temporary directory is empty
    When I scan empty input
    Then the temporary directory is empty

  @gitleaks
  Scenario: The temporary copy is removed when the scan fails
    Given the temporary directory is a folder of the scenario
    And gitleaks fails when it is run
    And a record "r" with the text "contact [email]"
    When I scan the records
    Then the exit code is 2
    And stderr contains "Gitleaks failed"
    And the temporary directory is empty
    And the output does not reveal the synthetic value

  # --- Files and directories ---------------------------------------------------------------------

  @gitleaks
  Scenario: A directory is scanned recursively and findings are listed by file and line
    Given a file "docs/guide.txt" with the text:
      """
      intro line
      reach us at [email]
      """
    And a file "docs/deep/more.txt" with the text:
      """
      nothing to see
      """
    When I run "leftblock scan docs"
    Then the exit code is 1
    And stdout contains "docs/guide.txt:2: leftblock-personal-email"
    And stdout does not contain "more.txt"

  @gitleaks
  Scenario: A single file is scanned, with the JSON output giving byte offsets into it
    Given a file "naïve notes.txt" with the text:
      """
      héllo 日本
      wallet_import = [wif]
      """
    When I run "leftblock scan --format json 'naïve notes.txt'"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.file" equal to "naïve notes.txt"
    And stdout is valid JSON with "findings.0.line" equal to "2"
    And stdout is valid JSON with "findings.0.rule" equal to "leftblock-wif-key"
    And stdout is valid JSON with "findings.0.kind" equal to "crypto"
    And finding 1 of the JSON output slices "naïve notes.txt" to [wif]

  @gitleaks
  Scenario: Several paths can be given and the WIF filter applies to files too
    Given a file "one.txt" with the text:
      """
      wallet_import = [bad wif]
      """
    And a file "two/b.txt" with the text:
      """
      contact [email]
      """
    When I run "leftblock scan --format json one.txt two"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.file" equal to "two/b.txt"
    And the JSON output has 1 finding

  @gitleaks
  Scenario: Clean files pass, and the JSON output says so
    Given a file "clean.txt" with the text:
      """
      An ordinary sentence.
      """
    When I run "leftblock scan --format json clean.txt"
    Then the exit code is 0
    And the JSON output has no findings

  @gitleaks
  Scenario: Board-data allowances apply to paths only
    Given a file "project/issues/ticket.json" with the text:
      """
      {"session_id": "[uuid]"}
      """
    And a record "ticket" with the text "session: [uuid]"
    When I run "leftblock scan project"
    Then the exit code is 0
    When I scan the records
    Then the exit code is 1
    And finding 1 of record "ticket" is for rule "leftblock-session-uuid" of kind "personal"

  @gitleaks
  Scenario: A missing path is an error
    When I run "leftblock scan no-such-folder"
    Then the exit code is 2
    And stderr contains "No such file or directory"
    And nothing is printed on stdout

  # --- Command line ------------------------------------------------------------------------------------

  Scenario Outline: Mistakes on the command line are errors with one line on stderr
    When I run "leftblock scan <arguments>"
    Then the exit code is 2
    And stderr contains "<message>"

    Examples:
      | arguments                | message                         |
      |                          | Give PATH... to scan            |
      | --jsonl some.txt         | do not also give paths          |
      | --jsonl --format json    | --format applies to paths       |
      | --labels secret some.txt | apply to --deep                 |
      | --threshold 0.5 some.txt | apply to --deep                 |
      | --deep --threshold 3 x   | --threshold must be a number    |
      | --deep --labels nope x   | Unknown label                   |

  Scenario: The help says what is and is not applied
    When I run "leftblock scan --help"
    Then the exit code is 0
    And stdout contains "--jsonl"
    And stdout contains "not applied"
    And stdout contains "--deep"

  @gitleaks
  Scenario: Scanning needs no Git repository
    Given a folder that is not inside any Git repository
    And a file "free/text.txt" with the text:
      """
      contact [email]
      """
    And a record "r" with the text "contact [email]"
    When I run "leftblock scan free"
    Then the exit code is 1
    When I scan the records
    Then the exit code is 1
    And finding 1 of record "r" slices to [email]

  # --- The deep scan -------------------------------------------------------------------------------------

  @gitleaks
  Scenario: With --deep the model's findings join the rules', as byte offsets
    Given the deep scan model is replaced by a stub detector
    And the model recognises [flagged] as secret at 0.97
    And a record "t" with the text "héllo 日本 😀 token [flagged] and mail [email]"
    When I scan the records with "--deep"
    Then the exit code is 1
    And the scan reports 2 findings
    And finding 1 of record "t" is for rule "privacy-filter-secret" of kind "deep"
    And finding 1 of record "t" slices to [flagged]
    And finding 1 of record "t" has score 0.97
    And finding 2 of record "t" is for rule "leftblock-personal-email" of kind "personal"
    And the output does not reveal the synthetic value

  @gitleaks
  Scenario: The deep scan keeps its defaults: a threshold, default labels and shape filters
    Given the deep scan model is replaced by a stub detector
    And the model recognises [flagged] as secret at 0.5
    And the model recognises [person] as private_person at 0.99
    And a record "t" with the text "token [flagged] belongs to [person]"
    When I scan the records with "--deep"
    Then the exit code is 0
    And the scan reports 0 findings
    When I scan the records with "--deep --threshold 0.4 --labels private_person"
    Then the scan reports 2 findings
    And finding 1 of record "t" slices to [flagged]
    And finding 2 of record "t" slices to [person]

  @gitleaks
  Scenario: Identifier shapes the model calls secrets are dropped, as in the deep scan
    Given the deep scan model is replaced by a stub detector
    And the model recognises [digest] as secret at 0.99
    And a record "t" with the text "built from [digest]"
    When I scan the records with "--deep"
    Then the exit code is 0

  @gitleaks
  Scenario: The model is consulted only when asked, and not for empty input
    Given the deep scan model is replaced by a stub detector
    And the model recognises [flagged] as secret at 0.97
    And a record "t" with the text "token [flagged]"
    When I scan the records
    Then the exit code is 0
    And the model was never consulted
    When I scan empty input
    Then the exit code is 0
    And the model was never consulted

  @gitleaks
  Scenario: Without the optional extra, --deep explains how to install it
    Given the deep scan extra is not installed
    And a record "t" with the text "hello"
    When I scan the records with "--deep"
    Then the exit code is 2
    And stderr contains "pip install 'leftblock[deep]'"

  @gitleaks
  Scenario: The deep scan reads files too, with the line and byte offsets
    Given the deep scan model is replaced by a stub detector
    And the model recognises [flagged] as secret at 0.97
    And a file "notes/today.txt" with the text:
      """
      first line
      héllo token [flagged]
      """
    When I run "leftblock scan --deep --format json notes"
    Then the exit code is 1
    And stdout is valid JSON with "findings.0.rule" equal to "privacy-filter-secret"
    And stdout is valid JSON with "findings.0.line" equal to "2"
    And stdout is valid JSON with "findings.0.score" equal to "0.97"
    And finding 1 of the JSON output slices "notes/today.txt" to [flagged]
