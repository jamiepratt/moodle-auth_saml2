<?php
// This file is part of Moodle
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Behat tests for auth_saml2
 *
 * @package     auth_saml2
 * @author      Daniel Thee Roperto <daniel.roperto@catalyst-au.net>
 * @copyright   2018 Catalyst IT Australia {@link http://www.catalyst-au.net}
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// NOTE: no MOODLE_INTERNAL test here, this file may be required by behat before including /config.php.

use auth_saml2\admin\saml2_settings;
use auth_saml2\task\metadata_refresh;
use Behat\Behat\Hook\Scope\AfterStepScope;
use Behat\Mink\Exception\ExpectationException;
use Behat\Gherkin\Node\TableNode;

require_once(__DIR__ . '/../../../../lib/behat/behat_base.php');

/**
 * Behat tests for auth_saml2
 *
 * @package     auth_saml2
 * @author      Daniel Thee Roperto <daniel.roperto@catalyst-au.net>
 * @copyright   2018 Catalyst IT Australia {@link http://www.catalyst-au.net}
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_auth_saml2 extends behat_base {
    /** @var string Last captured self-test response. */
    private string $lastselftestresponse = '';

    /** @var string Last captured metadata approval response. */
    private string $lastmetadataapprovalresponse = '';

    /** @var string Fingerprint of metadata active before a staged change. */
    private string $activemetadatafingerprint = '';

    /**
     * Confirms the Authentication plugin is enabled
     *
     * @param bool $enabled
     * @Given /^the authentication plugin saml2 is (disabled|enabled) +\# auth_saml2$/
     */
    public function the_authentication_plugin_is_enabled_auth_saml($enabled = true) {
        // If using SAML2 functionality, ensure all sessions are reset.
        $this->reset_moodle_session();

        if (($enabled == 'disabled') || ($enabled === false)) {
            set_config('auth', '');
        } else {
            set_config('auth', 'saml2');
            $this->initialise_saml2();
        }

        \core\session\manager::gc(); // Remove stale sessions.
        core_plugin_manager::reset_caches();
    }

    /**
     * Goes to the login/self test page
     *
     * @param string $page
     * @Given /^I go to the (login|self-test) page +\# auth_saml2$/
     */
    public function i_go_to_the_login_page_auth_saml($page) {
        switch ($page) {
            case 'login':
                $page = '/login/index.php';
                break;
            case 'self-test':
                $page = '/auth/saml2/test.php';
                break;
        }
        $this->getSession()->visit($this->locate_path($page));
    }

    /**
     * Request the self-test page without leaving Behat on an expected exception page.
     *
     * @When /^I request the self-test page +\# auth_saml2$/
     */
    public function i_request_the_self_test_page_auth_saml(): void {
        $this->getSession()->visit($this->locate_path('/auth/saml2/test.php'));
        $this->lastselftestresponse = $this->getSession()->getPage()->getContent();
        $this->getSession()->visit($this->locate_path('/'));
    }

    /**
     * Assert text in the captured self-test response.
     *
     * @param string $expected Expected response text.
     * @Then /^the self-test response should contain "([^"]*)" +\# auth_saml2$/
     */
    public function the_self_test_response_should_contain_auth_saml(string $expected): void {
        if (!str_contains($this->lastselftestresponse, $expected)) {
            throw new ExpectationException(
                "The self-test response did not contain '{$expected}'.",
                $this->getSession()
            );
        }
    }

    /**
     * Go to the auth_saml2 login page.
     *
     * @param string $parameters
     * @When /^I go to the login page with "([^"]*)" +\# auth_saml2$/
     */
    public function i_go_to_the_login_page_with_auth_saml($parameters) {
        $this->getSession()->visit($this->locate_path("login/index.php?{$parameters}"));
    }

    /**
     * Log in as admin.
     *
     * @Given /^I am an administrator +\# auth_saml2$/
     */
    public function im_an_administrator_auth_saml() {
        return $this->execute('behat_auth::i_log_in_as', ['admin']);
    }

    /**
     * Go to the saml2 settings page.
     *
     * @Given /^I am on the saml2 settings page +\# auth_saml2$/
     * @Then /^I go to the saml2 settings page (?:again) +\# auth_saml2$/
     */
    public function i_go_to_the_samlsettings_page_auth_saml() {
        $this->getSession()->visit($this->locate_path('/admin/settings.php?section=authsettingsaml2'));
    }

    /**
     * Change the setting to auth_saml
     *
     * @param string $field
     * @param string $value
     * @When /^I change the setting "([^"]*)" to "([^"]*)" +\# auth_saml2$/
     */
    public function i_change_the_setting_to_auth_saml($field, $value) {
        $this->execute('behat_forms::i_set_the_field_to', [$field, $value]);
    }

    /**
     * The setting should be auth_saml
     *
     * @param string $field
     * @param string $expectedvalue
     * @Given /^the setting "([^"]*)" should be "([^"]*)" +\# auth_saml2$/
     */
    public function the_setting_should_be_auth_saml($field, $expectedvalue) {
        $this->execute('behat_forms::the_field_matches_value', [$field, $expectedvalue]);
    }

    /**
     * Apply defaults
     */
    private function apply_defaults() {
        global $CFG;

        require_once($CFG->dirroot . '/auth/saml2/auth.php');

        // All integration test are over HTTP.
        set_config('cookiesecure', false);

        /** @var auth_plugin_saml2 $auth */
        $auth = get_auth_plugin('saml2');

        $defaults = array_merge($auth->defaults, [
            'autocreate'          => 1,
            'field_map_idnumber'  => 'uid',
            'field_map_email'     => 'email',
            'field_map_firstname' => 'firstname',
            'field_map_lastname'  => 'surname',
            'field_map_lang'      => 'lang',
        ]);

        foreach (['email', 'firstname', 'lastname', 'lang'] as $field) {
            $defaults["field_lock_{$field}"] = 'unlocked';
            $defaults["field_updatelocal_{$field}"] = 'oncreate';
        }

        foreach ($defaults as $key => $value) {
            set_config($key, $value, 'auth_saml2');
        }
    }

    /**
     * Initialise saml2
     */
    private function initialise_saml2() {
        $this->apply_defaults();
        require(__DIR__ . '/../../setup.php');
    }

    /**
     * Saml setting is set to auth_saml
     *
     * @param string $setting
     * @param string $value
     * @Given /^the saml2 setting "([^"]*)" is set to "([^"]*)" +\# auth_saml2$/
     */
    public function the_saml_setting_is_set_to_auth_saml($setting, $value) {
        $map = [];

        if ($setting == 'Dual Login') {
            $setting = 'duallogin';
            $map = [
                'no'      => saml2_settings::OPTION_DUAL_LOGIN_NO,
                'yes'     => saml2_settings::OPTION_DUAL_LOGIN_YES,
                'passive' => saml2_settings::OPTION_DUAL_LOGIN_PASSIVE,
            ];
        }

        if ($setting == 'Group rules') {
            $setting = 'grouprules';
        }

        if ($setting == 'Account blocking response type') {
            $setting = 'flagresponsetype';
            $map = [
                'display custom message'   => saml2_settings::OPTION_FLAGGED_LOGIN_MESSAGE,
                'redirect to external url' => saml2_settings::OPTION_FLAGGED_LOGIN_REDIRECT,
            ];
        }

        if ($setting == 'Redirect URL') {
            $setting = 'flagredirecturl';
        }

        if ($setting == 'Response message') {
            $setting = 'flagmessage';
        }

        $lowervalue = strtolower($value);
        $value = array_key_exists($lowervalue, $map) ? $map[$lowervalue] : $value;
        set_config($setting, $value, 'auth_saml2');
    }

    /**
     * Configures auth_saml2 to use the mock SAML IdP in tests/fixtures/mockidp.
     *
     * Also initialises certificates (if not done yet) and turns off secure cookies, in case you
     * are running Behat over http.
     *
     * @Given /^the mock SAML IdP is configured +\# auth_saml2$/
     */
    public function the_mock_saml_idp_is_configured() {
        global $CFG;
        $cert = file_get_contents(__DIR__ . '/../fixtures/mockidp/mock.crt');
        $cert = preg_replace('~(-----(BEGIN|END) CERTIFICATE-----)|\n~', '', $cert);
        $baseurl = $CFG->wwwroot . '/auth/saml2/tests/fixtures/mockidp';

        $metadata = <<<EOF
<md:EntityDescriptor entityID="{$baseurl}/idpmetadata.php" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false">
        <md:KeyDescriptor>
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data><X509Certificate>{$cert}</X509Certificate></X509Data>
            </KeyInfo>
        </md:KeyDescriptor>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="{$baseurl}/slo.php" />
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="{$baseurl}/sso.php" />
    </md:IDPSSODescriptor>
</md:EntityDescriptor>
EOF;

        // Update the config setting using the same method used in the UI.
        $idpmetadata = new \auth_saml2\admin\setting_idpmetadata();
        $idpmetadata->set_updatedcallback('auth_saml2_update_idp_metadata');
        $idpmetadata->write_setting($metadata);

        // Allow insecure cookies for Behat testing.
        set_config('cookiesecure', '0');

        // Turn auth_saml2 debugging on, required for self-test feature.
        set_config('debug', '1', 'auth_saml2');

        $auth = get_auth_plugin('saml2');
        if (!$auth->is_configured()) {
            require_once(__DIR__ . '/../../setuplib.php');
            create_certificates($auth);
        }
    }

    /**
     * Stage a signing-key rollover without activating it.
     *
     * @Given /^a SAML signing key change is pending +\# auth_saml2$/
     */
    public function a_saml_signing_key_change_is_pending(): void {
        $active = (string) get_config('auth_saml2', 'idpmetadata');
        $changed = preg_replace(
            '/(<X509Certificate>)(.)/',
            '$1Z',
            $active,
            1,
            $replacements
        );
        if ($replacements !== 1 || !is_string($changed)) {
            throw new ExpectationException('The active synthetic metadata has no signing certificate.', $this->getSession());
        }
        $this->activemetadatafingerprint = hash('sha256', $active);
        $result = (new \auth_saml2\admin\setting_idpmetadata())->validate($changed);
        if ($result !== get_string('idpmetadata_pendingapproval', 'auth_saml2')) {
            throw new ExpectationException('The synthetic signing-key change was not staged.', $this->getSession());
        }
    }

    /**
     * Visit the manual metadata approval page.
     *
     * @When /^I go to the SAML metadata approval page +\# auth_saml2$/
     */
    public function i_go_to_the_saml_metadata_approval_page(): void {
        $this->getSession()->visit($this->locate_path('/auth/saml2/metadata_approval.php'));
    }

    /**
     * Request the approval page without leaving Behat on an expected exception page.
     *
     * @When /^I request the SAML metadata approval page +\# auth_saml2$/
     */
    public function i_request_the_saml_metadata_approval_page(): void {
        $this->getSession()->visit($this->locate_path('/auth/saml2/metadata_approval.php'));
        $this->lastmetadataapprovalresponse = $this->getSession()->getPage()->getContent();
        $this->getSession()->visit($this->locate_path('/'));
    }

    /**
     * Assert text in the captured metadata approval response.
     *
     * @param string $expected Expected response text.
     * @Then /^the SAML metadata approval response should contain "([^"]*)" +\# auth_saml2$/
     */
    public function the_saml_metadata_approval_response_should_contain(string $expected): void {
        if (!str_contains($this->lastmetadataapprovalresponse, $expected)) {
            throw new ExpectationException(
                "The metadata approval response did not contain '{$expected}'.",
                $this->getSession()
            );
        }
    }

    /**
     * Attempt approval without a session key.
     *
     * @When /^I request SAML metadata activation without a session key +\# auth_saml2$/
     */
    public function i_request_saml_metadata_activation_without_a_session_key(): void {
        $path = '/auth/saml2/metadata_approval.php?confirm=1&outofband=1&authority=serviceowner';
        $this->getSession()->visit($this->locate_path($path));
    }

    /**
     * Assert that failed approval did not replace active metadata.
     *
     * @Then /^the SAML metadata change should remain pending and inactive +\# auth_saml2$/
     */
    public function the_saml_metadata_change_should_remain_pending_and_inactive(): void {
        $active = (string) get_config('auth_saml2', 'idpmetadata');
        if (
            !(new \auth_saml2\metadata_trust_manager())->has_pending() ||
            !hash_equals($this->activemetadatafingerprint, hash('sha256', $active))
        ) {
            throw new ExpectationException('The staged metadata was activated or discarded.', $this->getSession());
        }
    }

    /**
     * Assert that approval consumed the proposal and replaced active metadata.
     *
     * @Then /^the SAML metadata change should be active +\# auth_saml2$/
     */
    public function the_saml_metadata_change_should_be_active(): void {
        global $DB;

        $active = (string) $DB->get_field('config_plugins', 'value', [
            'plugin' => 'auth_saml2',
            'name' => 'idpmetadata',
        ]);
        if (
            (new \auth_saml2\metadata_trust_manager())->has_pending() ||
            hash_equals($this->activemetadatafingerprint, hash('sha256', $active))
        ) {
            throw new ExpectationException('The reviewed metadata proposal was not activated.', $this->getSession());
        }
    }

    /**
     * Replace the pending change with valid XML whose entity ID resembles executable HTML.
     *
     * @Given /^the pending SAML proposal contains HTML-like identifiers +\# auth_saml2$/
     */
    public function the_pending_saml_proposal_contains_html_like_identifiers(): void {
        $active = (string) get_config('auth_saml2', 'idpmetadata');
        $entityid = 'https://review.example/&quot;&gt;&lt;script id=&quot;saml-pending-xss&quot;&gt;' .
            'alert(1)&lt;/script&gt;';
        $changed = preg_replace('/entityID="[^"]+"/', 'entityID="' . $entityid . '"', $active, 1, $replacements);
        $result = (new \auth_saml2\admin\setting_idpmetadata())->validate($changed);
        if ($replacements !== 1 || $result !== get_string('idpmetadata_pendingapproval', 'auth_saml2')) {
            throw new ExpectationException('The HTML-like metadata proposal was not staged.', $this->getSession());
        }
    }

    /**
     * Assert that all safe approval details are shown and markup-like values remain text.
     *
     * @Then /^the exact pending SAML proposal details should be visible and escaped +\# auth_saml2$/
     */
    public function the_exact_pending_saml_proposal_details_should_be_visible_and_escaped(): void {
        $manager = new \auth_saml2\metadata_trust_manager();
        $review = $manager->get_pending_review();
        $pending = $manager->get_pending_data($review['proposalfingerprint']);
        $page = $this->getSession()->getPage();
        $text = $page->getText();

        $expected = [$review['proposalfingerprint']];
        foreach ($pending['descriptor']['sources'] as $source) {
            $expected[] = $source['source'];
            foreach ($source['entities'] as $entity) {
                $expected[] = $entity['entityid'];
                $expected = array_merge($expected, $entity['signingkeys']);
                foreach ($entity['endpoints'] as $endpoint) {
                    $expected = array_merge($expected, array_filter($endpoint, static fn(string $value): bool => $value !== ''));
                }
            }
        }
        foreach ($expected as $value) {
            if (!str_contains($text, $value)) {
                throw new ExpectationException("The proposal detail '{$value}' was not visible.", $this->getSession());
            }
        }
        $hidden = $page->find('css', 'input[name="proposalfingerprint"]');
        if ($hidden === null || !hash_equals($review['proposalfingerprint'], (string) $hidden->getValue())) {
            throw new ExpectationException('The visible and submitted proposal fingerprints differ.', $this->getSession());
        }
        if ($page->find('css', '#saml-pending-xss') !== null) {
            throw new ExpectationException('Metadata content was interpreted as executable HTML.', $this->getSession());
        }
    }

    /**
     * Confirms a user's login from the IdP, and returns information back to Moodle.
     *
     * This step must be used while at the mock IdP 'login' screen.
     *
     * @param mixed $passive
     * @param TableNode $data Table of attributes
     * @When /^the mock SAML IdP allows ((?:passive )?)login with the following attributes: +\# auth_saml2$/
     */
    public function the_mock_saml_idp_allows_login_with_the_following_attributes($passive, TableNode $data) {
        // Check the correct page is current.
        $this->find(
            'xpath',
            '//h1[normalize-space(.)="Mock IdP login"]',
            new ExpectationException('Not on the IdP login page.', $this->getSession())
        );

        // Find out if it's in passive mode.
        $pagepassive = $this->getSession()->getDriver()->find('//h2[normalize-space(.)="Passive mode"]');
        if ($passive && !$pagepassive) {
            throw new ExpectationException('Expected passive mode, but not passive.', $this->getSession());
        } else if (!$passive && $pagepassive) {
            throw new ExpectationException('Expected not passive mode, but passive.', $this->getSession());
        }

        // Work out the JSON data.
        $out = new \stdClass();
        foreach ($data->getRowsHash() as $key => $value) {
            $out->{$key} = $value;
        }
        $json = json_encode($out);

        // Set the field and press the submit button.
        $this->getSession()->getDriver()->setValue('//textarea', $json);
        $this->getSession()->getDriver()->click('//button[@id="login"]');
    }

    /**
     * After a passive login attempt, when the IdP confirms that the user is not logged in.
     *
     * @Given /^the mock SAML IdP does not allow passive login +\# auth_saml2$/
     */
    public function the_mock_saml_idp_does_not_allow_passive_login() {
        // Check the correct page is current.
        $this->find(
            'xpath',
            '//h1[normalize-space(.)="Mock IdP login"]',
            new ExpectationException('Not on the IdP login page.', $this->getSession())
        );

        $this->find(
            'xpath',
            '//h2[normalize-space(.)="Passive mode"]',
            new ExpectationException('Expected passive mode, but not passive.', $this->getSession())
        );

        // Press the no-login button.
        $this->getSession()->getDriver()->click('//button[@id="nologin"]');
    }

    /**
     * Confirms logout from the IdP.
     *
     * This step must be used while at the mock IdP 'logout' screen.
     *
     * @When /^the mock SAML IdP confirms logout +\# auth_saml2$/
     */
    public function the_mock_saml_idp_confirms_logout() {
        // Check the correct page is current.
        $this->find(
            'xpath',
            '//h1[normalize-space(.)="Mock IdP logout"]',
            new ExpectationException('Not on the IdP logout page.', $this->getSession())
        );

        // Press the submit button.
        $this->getSession()->getDriver()->click('//button');
    }

    /**
     * Sets a cookie (for use testing the autologin based on cookie).
     *
     * @param string $cookiename
     * @param array $value
     * @When /^the cookie "([^"]+)" is set to "([^"]+)" +\# auth_saml2$/
     */
    public function the_cookie_is_set_to($cookiename, $value) {
        $this->getSession()->getDriver()->executeScript('document.cookie = "' .
                addslashes_js($cookiename) . '=' . addslashes_js($value) . '";');
    }

    /**
     * Clears a cookie (for use testing the autologin based on cookie).
     *
     * @param string $cookiename
     * @When /^the cookie "([^"]+)" is removed +\# auth_saml2$/
     */
    public function the_cookie_is_removed($cookiename) {
        $this->getSession()->getDriver()->executeScript('document.cookie = "' .
                addslashes_js($cookiename) . '=; expires=Thu, 01 Jan 1970 00:00:00 GMT";');
    }

    /**
     * Submits a POST request to the site homepage.
     *
     * @When /^I submit a POST request to site homepage +\# auth_saml2$/
     */
    public function i_submit_a_post_request_to_site_homepage(): void {
        $this->getSession()->getDriver()->executeScript(<<<JS
            const form = document.createElement('form');
            form.method = 'post';
            form.action = window.location.href;
            document.body.appendChild(form);
            form.submit();
            JS);
    }

    /**
     * Visist saml2 login page.
     */
    private function visit_saml2_login_page() {
        $this->getSession()->visit($this->locate_path('http://simplesamlphp.test:8001/module.php/core/authenticate.php'));
    }

    /**
     * Reset saml2 session.
     */
    private function reset_saml2_session() {
        $this->visit_saml2_login_page();
        $this->getSession()->reset();
    }

    /**
     * Reset moodle session.
     */
    private function reset_moodle_session() {
        $this->i_go_to_the_login_page_with_auth_saml('saml=off');
        $this->getSession()->reset();
    }
}
