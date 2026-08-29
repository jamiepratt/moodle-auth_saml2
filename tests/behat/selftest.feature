@auth @auth_saml2 @auth_saml2_diagnostic @javascript
Feature: Self tests
  In order to test for known configuration issues
  As a site administrator
  I should be able to run self tests

  Scenario: Anonymous users must log in before accessing the self test page
    Given the authentication plugin saml2 is enabled  # auth_saml2
    And the mock SAML IdP is configured               # auth_saml2
    When I go to the self-test page                   # auth_saml2
    Then I should see "Log in"

  Scenario: Ordinary authenticated users cannot access the self test page
    Given the authentication plugin saml2 is enabled    # auth_saml2
    And the mock SAML IdP is configured                 # auth_saml2
    And the following "users" exist:
      | username | firstname | lastname | email              |
      | student  | Sam       | Student  | student@example.com |
    And I log in as "student"
    When I request the self-test page                   # auth_saml2
    Then the self-test response should contain "do not currently have permissions" # auth_saml2

  Scenario: Site administrators can access the self test page
    Given the authentication plugin saml2 is enabled  # auth_saml2
    And the mock SAML IdP is configured               # auth_saml2
    And I am an administrator                         # auth_saml2
    When I go to the self-test page                   # auth_saml2
    Then I should not see "Error"

  Scenario: Site administrators cannot access the self test page while debugging is disabled
    Given the authentication plugin saml2 is enabled  # auth_saml2
    And I am an administrator                         # auth_saml2
    When I request the self-test page                  # auth_saml2
    Then the self-test response should contain "SAML debugging must be on" # auth_saml2
