@auth @auth_saml2 @auth_saml2_cache_coherence
Feature: SAML2 acceptance setup
  In order to exercise SAML over the disposable HTTP test site
  As an acceptance test
  I need insecure test cookies to be effective after each SAML setup path

  Scenario: Enabling SAML repairs a stale secure-cookie cache
    Given the following config values are set as admin:
      | auth | saml2 |
    And the insecure-cookie database and config cache disagree # auth_saml2
    When the authentication plugin saml2 is enabled                             # auth_saml2
    Then insecure test cookies should be effective                              # auth_saml2

  Scenario: Configuring the mock IdP repairs a stale secure-cookie cache
    Given the authentication plugin saml2 is enabled                            # auth_saml2
    And the insecure-cookie database and config cache disagree                  # auth_saml2
    When the mock SAML IdP is configured                                        # auth_saml2
    Then insecure test cookies should be effective                              # auth_saml2
