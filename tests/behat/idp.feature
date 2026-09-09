@auth @auth_saml2 @auth_saml2_moodle_idp @javascript
Feature: Moodle IdP trusts only registered service destinations
  In order to protect learner profile attributes
  As an administrator
  I must explicitly register service provider ACS destinations

  Background:
    Given the authentication plugin saml2 is enabled # auth_saml2
    And the mock SAML IdP is configured # auth_saml2
    And the following "users" exist:
      | username | firstname | lastname | email              |
      | learner  | Synthetic | Learner  | learner@example.test |
    And I log in as "learner"

  Scenario: Disabled Moodle IdP ignores a retained legacy SP list
    Given the Moodle IdP registration is "disabled" # auth_saml2
    When I send a synthetic Moodle IdP request to the "attacker" ACS # auth_saml2
    Then the synthetic SP should have received 0 assertions # auth_saml2
    And the Moodle IdP response should contain "Moodle IDP is not enabled" # auth_saml2

  Scenario: Approved ACS receives a signed response for the current learner
    Given the Moodle IdP registration is "approved" # auth_saml2
    When I send a synthetic Moodle IdP request to the "approved" ACS # auth_saml2
    Then the synthetic SP should have received 1 assertions # auth_saml2
    And the Moodle IdP response should contain "Registered SP received a signed assertion" # auth_saml2

  Scenario: Request-supplied attacker ACS receives no response
    Given the Moodle IdP registration is "approved" # auth_saml2
    When I send a synthetic Moodle IdP request to the "attacker" ACS # auth_saml2
    Then the synthetic SP should have received 0 assertions # auth_saml2
    And the Moodle IdP response should contain "cannot accept this authentication request" # auth_saml2

  Scenario: Legacy registration cannot issue an assertion until ACS trust is configured
    Given the Moodle IdP registration is "legacy" # auth_saml2
    When I send a synthetic Moodle IdP request to the "approved" ACS # auth_saml2
    Then the synthetic SP should have received 0 assertions # auth_saml2
    And the Moodle IdP response should contain "register an explicit ACS URL" # auth_saml2

  Scenario: Metadata advertises the actual supported subject identifier
    Given the Moodle IdP registration is "approved" # auth_saml2
    When I request the Moodle IdP metadata # auth_saml2
    Then the Moodle IdP response should contain "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" # auth_saml2
