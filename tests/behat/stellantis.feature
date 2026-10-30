@auth_saml2_stellantis @javascript
Feature: Synthetic Stellantis-like HTTPS protocol compatibility
  Simulation tests hypotheses and cannot qualify the real provider.

  Background:
    Given the following "users" exist:
      | username     | auth  | firstname | lastname |
      | zz1234567890 | saml2 | Synthetic | Learner  |

  Scenario Outline: A request baseurl cannot change metadata or the signed login destination
    Given the isolated Stellantis profile uses "<binding>"
    When I visit "/auth/saml2/sp/metadata.php?output=xhtml&baseurl=https%3A%2F%2Fforeign.example.test%2Fother"
    Then I should see "https://sp.saml.test/auth/saml2/sp/metadata.php"
    And I should not see "foreign.example.test"
    When I visit "/auth/saml2/login.php?saml=on&baseurl=https%3A%2F%2Fforeign.example.test%2Fother"
    Then I should see "Binding: <binding>"
    When I press "Continue to Moodle"
    Then I should see "Synthetic Learner"
    And the Stellantis account remains unique without new grants
    Examples:
      | binding       |
      | HTTP-Redirect |
      | HTTP-POST     |

  Scenario Outline: Independent signatures survive a cross-site POST with secure cookies
    Given the isolated Stellantis profile uses "<binding>"
    And the Stellantis response variant is "<variant>"
    When I start "<mode>" Stellantis login
    Then I should see "Binding: <actual>"
    When I press "Continue to Moodle"
    Then I should see "Synthetic Learner"
    And the Stellantis account remains unique without new grants
    And the Stellantis browser uses validated TLS and secure cookies
    And the "<mode>" Stellantis landing preserves RelayState
    Examples:
      | binding       | variant         | mode        | actual        |
      | HTTP-Redirect | valid           | solicited   | HTTP-Redirect |
      | HTTP-POST     | valid           | solicited   | HTTP-POST     |
      | HTTP-Redirect | combined        | solicited   | HTTP-Redirect |
      | HTTP-Redirect | encrypted       | solicited   | HTTP-Redirect |
      | HTTP-Redirect | response-signed | solicited   | HTTP-Redirect |
      | HTTP-Redirect | skew            | solicited   | HTTP-Redirect |
      | HTTP-Redirect | valid           | unsolicited | unsolicited   |

  Scenario: The upgraded transient default is rejected by the unspecified-only profile
    Given the isolated Stellantis profile uses "HTTP-Redirect"
    And the saml2 setting "nameidpolicy" is set to "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" # auth_saml2
    When I start "solicited" Stellantis login
    Then I should see "Unsupported NameIDPolicy"

  Scenario Outline: Invalid assertions cannot establish a Moodle session
    Given the isolated Stellantis profile uses "HTTP-Redirect"
    And the Stellantis response variant is "<variant>"
    When I start "solicited" Stellantis login
    And I submit the rejected Stellantis response
    Then Stellantis authentication must have been rejected
    And the Stellantis account remains unique without new grants
    Examples:
      | variant     |
      | tampered    |
      | untrusted   |
      | issuer      |
      | audience    |
      | destination |
      | recipient   |
      | correlation |
      | expired     |
      | future      |

  Scenario Outline: Local logout retains the synthetic IdP session and repeat login creates no grants
    Given the isolated Stellantis profile uses "HTTP-Redirect"
    And the saml2 setting "attemptsignout" is set to "<attempt>" # auth_saml2
    When I start "solicited" Stellantis login
    And I press "Continue to Moodle"
    And I log out through Moodle
    And I start "solicited" Stellantis login
    Then I should see "Retained IdP session: yes"
    When I press "Continue to Moodle"
    Then I should see "Synthetic Learner"
    And the Stellantis account remains unique without new grants
    Examples:
      | attempt |
      | 0       |
      | 1       |

  Scenario: A slow IdP journey keeps cross-site session continuity
    Given the isolated Stellantis profile uses "HTTP-Redirect"
    When I start "solicited" Stellantis login
    And I wait beyond the cross-site cookie grace period
    And I press "Continue to Moodle"
    Then I should see "Synthetic Learner"
    And the Stellantis browser uses validated TLS and secure cookies

  Scenario: An unsolicited assertion cannot be replayed after local logout
    Given the isolated Stellantis profile uses "HTTP-Redirect"
    When I start "unsolicited" Stellantis login
    And I press "Continue to Moodle"
    Then I should see "Synthetic Learner"
    When I log out through Moodle
    And I start "replay" Stellantis login
    And I submit the rejected Stellantis response
    Then Stellantis authentication must have been rejected

  Scenario Outline: Independent manual administrators remain available during IdP failure
    Given the following "users" exist:
      | username | auth   | firstname | lastname | password           |
      | localone | manual | Local     | One      | Synthetic-pass-12! |
      | localtwo | manual | Local     | Two      | Synthetic-pass-12! |
    And the user "localone" is a site administrator # auth_saml2
    And the user "localtwo" is a site administrator # auth_saml2
    And the isolated Stellantis profile uses "HTTP-Redirect"
    And the Stellantis response variant is "<variant>"
    When I start "solicited" Stellantis login
    Then I should see "<message>"
    When I authenticate local administrator "localone"
    Then I should see "Site administration"
    When I log out through Moodle
    And I authenticate local administrator "localtwo"
    Then I should see "Site administration"
    When I log out through Moodle
    Then I should see "Log in"
    Examples:
      | variant | message                   |
      | outage  | Synthetic IdP unavailable |
      | valid   | Synthetic IdP             |

  Scenario: Signed UID-only login creates an incomplete account without reporting data
    Given the isolated Stellantis profile uses "HTTP-Redirect"
    And the Stellantis identity is a new account
    When I start "solicited" Stellantis login
    And I press "Continue to Moodle"
    Then I should see "Email address"
    And the new Stellantis account requires profile completion

  Scenario: Rejected authentication leaves both local administrator password logins available
    Given the following "users" exist:
      | username | auth   | firstname | lastname | password           |
      | localone | manual | Local     | One      | Synthetic-pass-12! |
      | localtwo | manual | Local     | Two      | Synthetic-pass-12! |
    And the user "localone" is a site administrator # auth_saml2
    And the user "localtwo" is a site administrator # auth_saml2
    And the isolated Stellantis profile uses "HTTP-Redirect"
    And the Stellantis response variant is "tampered"
    When I start "solicited" Stellantis login
    And I submit the rejected Stellantis response
    Then Stellantis authentication must have been rejected
    When I authenticate local administrator "localone"
    Then I should see "Site administration"
    When I log out through Moodle
    And I authenticate local administrator "localtwo"
    Then I should see "Site administration"
    When I log out through Moodle
    Then I should see "Log in"
