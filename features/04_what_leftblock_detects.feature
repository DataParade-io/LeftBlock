@gitleaks
Feature: What LeftBlock detects
  As a developer
  I want the shipped rules to recognise the kinds of material I must not commit
  So that a fresh install protects me without any configuration of my own

  The default ruleset covers personal data (emails, home-folder paths,
  identifiers), cloud and AI provider credentials and crypto wallet secrets,
  on top of gitleaks' own default secret rules. Public values that merely look
  similar are left alone so the gate does not cry wolf: no-reply and
  reserved placeholder addresses, GitHub identities, public wallet addresses,
  digests, ordinary prose and hex blobs with no key context. A Bitcoin WIF key
  is recognised by its shape and then confirmed by its base58check checksum
  and layout, so a random run of look-alike characters (inside a base64 font
  or image, say) is not flagged. AI provider keys
  have their own chapter; Kanbus board data has another.

  Scenario Outline: A staged <kind> is blocked by its rule
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "data.txt" containing a synthetic <kind>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value

    Examples:
      | kind                 | rule                       |
      | personal email       | leftblock-personal-email   |
      | home path            | leftblock-home-path-posix  |
      | Windows home path    | leftblock-home-path-windows |
      | session UUID         | leftblock-session-uuid     |
      | actor id             | leftblock-actor-id         |
      | AWS key pair         | aws-access-token           |
      | Ethereum private key | leftblock-eth-private-key  |
      | Bitcoin WIF key      | leftblock-wif-key          |
      | seed phrase          | leftblock-bip39-mnemonic   |

  Scenario Outline: Home folders on Linux, other wallet key shapes and gitleaks' own rules are blocked too
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "data.txt" containing a synthetic <kind>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "<rule>"
    And the output does not reveal the synthetic value

    Examples:
      | kind                          | rule                      |
      | Linux home path               | leftblock-home-path-posix |
      | uncompressed WIF key          | leftblock-wif-key         |
      | labelled bare and 0x-prefixed hex private keys | leftblock-eth-private-key |
      | labelled bare hex private key | generic-api-key          |
      | Google API key                | gcp-api-key               |

  Scenario Outline: A seed phrase is recognised at every standard length
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "wallet.txt" containing a synthetic <length>-word seed phrase
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-bip39-mnemonic"
    And the output does not reveal the synthetic value

    Examples:
      | length |
      | 12     |
      | 15     |
      | 18     |
      | 21     |
      | 24     |

  Scenario Outline: A seed phrase is recognised however its assignment is written
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "wallet.txt" containing a synthetic <shape>
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-bip39-mnemonic"
    And the output does not reveal the synthetic value

    Examples:
      | shape                                 |
      | quoted seed phrase assignment         |
      | tightly quoted seed phrase assignment |
      | colon mnemonic line                   |
      | quoted vault seed assignment          |

  Scenario Outline: A personal-looking address is blocked, including look-alikes of the exempt ones
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.md" containing an address "<local>" at "<domain>"
    When I commit the staged files
    Then the commit is blocked
    And stderr contains "leftblock-personal-email"
    And the output does not reveal the synthetic value

    Examples:
      | local      | domain         |
      | jo         | vendor.co      |
      | notnoreply | vendor.co      |
      | jo         | test.com       |
      | jo         | invalid.org    |
      | jo         | example.test.co |
      | jo         | mytest.dev     |
      | jo         | example.edu.co |
      | jo         | notexample.edu |

  Scenario Outline: No-reply addresses, GitHub identities and reserved placeholder domains are not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "notes.md" containing an address "<local>" at "<domain>"
    When I commit the staged files
    Then the commit succeeds

    Examples:
      | local        | domain                     | why                                  |
      | noreply      | vendor.co                  | no-reply address                     |
      | no-reply     | vendor.co                  | hyphenated no-reply address          |
      | 12345+person | users.noreply.github.com   | GitHub noreply identity              |
      | git          | github.com                 | GitHub SSH identity                  |
      | person       | example.com                | example.com placeholder              |
      | person       | example.org                | example.org placeholder              |
      | person       | example.invalid            | reserved .invalid domain             |
      | a            | mail.acme.test             | reserved .test domain                |
      | b            | deep.sub.host.example      | reserved .example domain, any depth  |
      | c            | app.localhost              | reserved .localhost domain           |
      | d            | example.edu                | RFC 2606 example.edu                 |
      | e            | x.test                     | shortest .test domain                |

  Scenario: Ordinary prose, a placeholder user folder and clean code are not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "README.md" containing:
      """
      the team will review the release plan early tomorrow morning
      and confirm whether the database migration can proceed as planned
      Builds run under /Users/example/ci on the shared runner.
      """
    And a staged file "main.rs" containing:
      """
      fn main() {
          let config_path = std::env::var("CONFIG_PATH");
          println!("hello world");
      }
      """
    And a staged file "config.toml" containing:
      """
      [server]
      host = "0.0.0.0"
      port = 8080
      """
    When I commit the staged files
    Then the commit succeeds

  Scenario: A WIF-shaped string whose checksum does not verify is not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "wallet.txt" containing a synthetic WIF-shaped string with a bad checksum
    When I commit the staged files
    Then the commit succeeds

  Scenario: A WIF-shaped run inside a base64 font in minified CSS is not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "vendor.css" containing a synthetic minified stylesheet with a font data URI holding a WIF-shaped run
    When I commit the staged files
    Then the commit succeeds

  Scenario: A valid compressed WIF key is flagged by its rule
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "wallet.txt" containing a synthetic Bitcoin WIF key
    When I run "leftblock check"
    Then the exit code is 1
    And stderr contains "leftblock-wif-key"
    And the output does not reveal the synthetic value

  Scenario: Public wallet addresses and digests are not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "addresses.txt" containing a synthetic public wallet address and digest
    When I commit the staged files
    Then the commit succeeds

  Scenario: A Bitcoin address, a git commit id and a SHA-512 digest are not flagged
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "hashes.txt" containing a synthetic Bitcoin address and git and SHA-512 digests
    When I commit the staged files
    Then the commit succeeds

  Scenario: A 64-digit hex blob with no key context is left alone
    Given a repository with LeftBlock installed as a local check-only gate
    And a staged file "blob.txt" containing a synthetic unlabelled hex blob
    When I commit the staged files
    Then the commit succeeds
