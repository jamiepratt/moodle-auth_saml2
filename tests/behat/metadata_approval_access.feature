@auth @auth_saml2 @auth_saml2_metadata_trust @javascript
Feature: SAML metadata approval access
  In order to prevent unauthorised trust changes
  As a standard Moodle user
  I must not have access to SAML metadata approval

  Scenario: Approval requires the site configuration capability
    Given the following "users" exist:
      | username | password | firstname | lastname | auth   |
      | learner1 | test     | Standard  | User     | manual |
    And the authentication plugin saml2 is enabled                           # auth_saml2
    And the mock SAML IdP is configured                                      # auth_saml2
    And a SAML signing key change is pending                                 # auth_saml2
    When I go to the login page with "saml=off"                              # auth_saml2
    And I set the field "Username" to "learner1"
    And I set the field "Password" to "test"
    And I press "Log in"
    And I request the SAML metadata approval page                            # auth_saml2
    Then the SAML metadata approval response should contain "do not currently have permissions" # auth_saml2
    And the SAML metadata change should remain pending and inactive          # auth_saml2
