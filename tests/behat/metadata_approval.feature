@auth @auth_saml2 @auth_saml2_metadata_trust @javascript
Feature: Manual SAML metadata approval
  In order to retain established SAML trust
  As a site administrator
  I need security-relevant metadata changes to require explicit protected approval

  Background:
    Given the authentication plugin saml2 is enabled                           # auth_saml2
    And the mock SAML IdP is configured                                        # auth_saml2
    And I am an administrator                                                  # auth_saml2
    And a SAML signing key change is pending                                   # auth_saml2

  Scenario: Approval requires out-of-band confirmation
    When I go to the SAML metadata approval page                               # auth_saml2
    Then I should see "Activate only after"
    And I should see "I confirm that the IdP change was verified"
    When I press "Approve and activate"
    Then I should see "Out-of-band IdP confirmation is required before activation."
    And the SAML metadata change should remain pending and inactive            # auth_saml2

  Scenario: Approval requires a valid session key
    When I request SAML metadata activation without a session key              # auth_saml2
    Then I should see "Your session has most likely timed out"
    And the SAML metadata change should remain pending and inactive            # auth_saml2
