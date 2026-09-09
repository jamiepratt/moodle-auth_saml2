@auth @auth_saml2 @auth_saml2_selector @javascript
Feature: Metadata is data on SAML selectors
  In order to select a trusted provider safely
  As a user or administrator
  I need refreshed metadata labels and logos to remain inert

  Scenario: Unauthenticated buttons preserve safe logos and remembered dropdown selection
    Given the authentication plugin saml2 is enabled # auth_saml2
    And refreshed inert multi-IdP metadata is configured # auth_saml2
    When I visit the SAML buttons selector # auth_saml2
    Then the refreshed SAML buttons should contain only inert metadata # auth_saml2
    When I remember the normal SAML provider # auth_saml2
    And I visit the SAML buttons selector # auth_saml2
    Then the normal SAML provider should be remembered once # auth_saml2
    When I visit the SAML dropdown selector # auth_saml2
    Then the SAML dropdown should preserve metadata and selection # auth_saml2

  Scenario: Administrator names and entity source labels remain literal text
    Given the authentication plugin saml2 is enabled # auth_saml2
    And refreshed inert multi-IdP metadata is configured # auth_saml2
    And I log in as "admin"
    Then the SAML administrator labels should contain only inert metadata # auth_saml2
