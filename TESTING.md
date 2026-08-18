# Testing

The automated PHPUnit and Behat suites use synthetic fixtures committed under
`tests/fixtures`. The mock IdP is served from the disposable Moodle test site.
Automated tests must not contact a production or uncontrolled IdP and must not
contain production credentials, certificates, metadata, or user data.

Run the plugin suite from a moodle-plugin-ci installation configured for the
Moodle `v5.2.2` tag:

```sh
moodle-plugin-ci phpunit --fail-on-warning --fail-on-risky --fail-on-incomplete --fail-on-skipped
moodle-plugin-ci behat --profile chrome --scss-deprecations
moodle-plugin-ci behat --profile firefox --scss-deprecations
```

The following local manual exercises are useful when developing the synthetic
IdP fixture. They are not CI dependencies:

1) Test using 1 IdP (SSP) with dual off eg:

http://moodle.local/login/index.php


2) Test using mulitple IdP (SSP) with a choice of IdP eg:

http://moodle.local/auth/saml2/login.php?wants&idp=c4b9265e38e3107bee1ccdf9d6475676&passive=off


3) Test Single logout starting from the SP

http://moodle.local/login/logout.php?sesskey=ihwmEywPxu


4) Test Single logout starting from the IdP. Notice that `ReturnTo` URL domain should be in `trusted.url.domains` in IdP config.
If that is not the case, try using `ReturnTo=http://idp.local/simplesaml` which should work as SimpleSAMLphp trusts self hostname by default.

http://idp.local/simplesaml/saml2/idp/SingleLogoutService.php?ReturnTo=http://moodle.local/

5) Test IdP initiation login

http://idp.local/simplesaml/saml2/idp/SSOService.php?spentityid=http://moodle.local/auth/saml2/sp/metadata.php

6) Test IdP init login when the IdP is NOT the default IdP

http://idp.local/simplesaml/saml2/idp/SSOService.php?spentityid=http://moodle.local/auth/saml2/sp/metadata.php
