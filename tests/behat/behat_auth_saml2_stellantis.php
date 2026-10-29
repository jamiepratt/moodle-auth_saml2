<?php
// This file is part of Moodle - https://moodle.org/
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
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

use auth_saml2\fixture\protocol;
use Behat\Mink\Exception\ExpectationException;

require_once(__DIR__ . '/../../../../lib/behat/behat_base.php');
require_once(__DIR__ . '/../fixtures/stellantis/protocol.php');

/**
 * Cross-site HTTPS qualification of synthetic North American provider assumptions.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_auth_saml2_stellantis extends behat_base {
    /** @var string Captured rejection. */
    private string $rejection = '';

    /**
     * Configure only this explicitly selected disposable harness.
     *
     * @param string $binding Request binding.
     * @Given /^the isolated Stellantis profile uses "([^"]*)"$/
     */
    public function configure(string $binding): void {
        global $CFG;
        if (getenv('SAML12_HTTPS') !== '1' || $CFG->wwwroot !== 'https://sp.saml.test') {
            throw new RuntimeException('Requires the isolated SAML12 HTTPS harness');
        }
        $this->getSession()->visit('https://sp.saml.test/login/index.php?saml=off');
        $this->getSession()->reset();
        require_once(__DIR__ . '/../../auth.php');
        require_once(__DIR__ . '/../../setuplib.php');
        $auth = get_auth_plugin('saml2');
        foreach ($auth->defaults as $key => $value) {
            set_config($key, $value, 'auth_saml2');
        }
        foreach (
            ['autocreate' => 1, 'anyauth' => 0, 'idpattr' => 'uid', 'mdlattr' => 'username',
            'field_map_firstname' => '', 'field_map_lastname' => '', 'field_map_email' => '',
            'nameidpolicy' => protocol::NAMEID, 'duallogin' => 1, 'attemptsignout' => 0,
            'idpmetadatarefresh' => 0, 'wantassertionssigned' => 0] as $key => $value
        ) {
            set_config($key, $value, 'auth_saml2');
        }
        set_config('auth', 'saml2');
        set_config('cookiesecure', 1);
        set_config('cookiehttponly', 1);
        cache_helper::invalidate_by_definition('core', 'config', [], 'core');
        $setting = new \auth_saml2\admin\setting_idpmetadata();
        $setting->write_setting(protocol::metadata(file_get_contents('/fixture/idp.crt'), $binding));
        $auth = new \auth_plugin_saml2();
        $error = create_certificates($auth, false, 30);
        if ($error) {
            throw new RuntimeException($error);
        }
        file_put_contents('/var/www/data/saml12-sp.crt', file_get_contents($auth->certcrt));
        $this->variant('valid');
        @unlink('/var/www/data/saml12-response.xml');
    }

    /**
     * Select one explicit probe; unknown profiles cannot silently pass.
     *
     * @param string $variant Response variant.
     * @Given /^the Stellantis response variant is "([^"]*)"$/
     */
    public function variant(string $variant): void {
        $allowed = ['combined', 'encrypted', 'valid', 'response-signed', 'tampered', 'untrusted',
            'issuer', 'audience', 'destination',
            'recipient', 'correlation', 'expired', 'future', 'skew', 'outage'];
        if (!in_array($variant, $allowed, true)) {
            throw new RuntimeException('Unknown response variant');
        }
        file_put_contents('/var/www/data/saml12.json', json_encode([
            'attributes' => ['uid' => ['zz1234567890'], 'DealerCode' => ['D0001']],
            'variant' => $variant, 'unsolicited' => true,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * Start a browser request against the real SP, or an explicitly enabled unsolicited launch.
     *
     * @param string $mode Login mode.
     * @When /^I start "(solicited|unsolicited|replay)" Stellantis login$/
     */
    public function start(string $mode): void {
        $url = match ($mode) {
            'solicited' => 'https://sp.saml.test/login/index.php?saml=on',
            'unsolicited' => protocol::LAUNCH . '?PartnerSpId=' . urlencode(protocol::SP) .
                '&IdpAdapterId=SyntheticAdapter&TargetResource=' . urlencode('https://sp.saml.test/user/profile.php'),
            'replay' => protocol::SSO . '?replay=1',
        };
        $this->getSession()->visit($url);
    }

    /**
     * Submit a rejected response and return to a normal page before Behat's exception scanner.
     *
     * @When /^I submit the rejected Stellantis response$/
     */
    public function submit_rejected(): void {
        $this->getSession()->getPage()->pressButton('Continue to Moodle');
        $this->getSession()->wait(500);
        $this->rejection = $this->getSession()->getPage()->getContent();
        $this->getSession()->visit('https://sp.saml.test/login/index.php');
    }

    /**
     * Verify both protocol rejection and absence of a Moodle login session.
     *
     * @Then /^Stellantis authentication must have been rejected$/
     */
    public function rejected(): void {
        if (
            !preg_match('/(SAML2 exception|State information lost|Received duplicate assertion)/i', strip_tags($this->rejection)) ||
                $this->getSession()->getPage()->find('css', '#username') === null
        ) {
            throw new ExpectationException('Expected protocol rejection and an unauthenticated login page', $this->getSession());
        }
    }

    /**
     * Inspect the account/grant boundary independently of rendered profile text.
     *
     * @Then /^the Stellantis account remains unique without new grants$/
     */
    public function unique(): void {
        global $DB;
        $users = $DB->get_records('user', ['username' => 'zz1234567890']);
        if (count($users) !== 1) {
            throw new RuntimeException('Expected one account');
        }
        $user = reset($users);
        foreach (['role_assignments', 'user_enrolments', 'groups_members'] as $table) {
            if ($DB->record_exists($table, ['userid' => $user->id])) {
                throw new RuntimeException('Unexpected SAML grant: ' . $table);
            }
        }
    }
    /**
     * Assert actual browser cookies and TLS policy after a real login.
     *
     * @Then /^the Stellantis browser uses validated TLS and secure cookies$/
     */
    public function secure_browser(): void {
        $driver = $this->getSession()->getDriver()->getWebDriver();
        if ($driver->getCapabilities()->getCapability('acceptInsecureCerts')) {
            throw new RuntimeException('Browser certificate validation is disabled');
        }
        $found = [];
        foreach ($driver->manage()->getCookies() as $cookie) {
            if (
                str_starts_with($cookie['name'], 'MoodleSession') ||
                    in_array($cookie['name'], ['MDL_SSP_SessID', 'MDL_SSP_AuthToken'], true)
            ) {
                if (
                    !$cookie['secure'] || !$cookie['httpOnly'] ||
                        (str_starts_with($cookie['name'], 'MDL_SSP_') && ($cookie['sameSite'] ?? '') !== 'None')
                ) {
                    throw new RuntimeException('Insecure authentication cookie');
                }
                $found[] = $cookie['name'];
            }
        }
        if (!in_array('MDL_SSP_SessID', $found, true) || !in_array('MDL_SSP_AuthToken', $found, true)) {
            throw new RuntimeException('SAML session cookies missing');
        }
    }

    /**
     * The IdP launch target must survive the cross-site response.
     *
     * @param string $mode Login mode.
     * @Then /^the "(solicited|unsolicited)" Stellantis landing preserves RelayState$/
     */
    public function relay_landing(string $mode): void {
        if (
            $mode === 'unsolicited' &&
                parse_url($this->getSession()->getCurrentUrl(), PHP_URL_PATH) !== '/user/profile.php'
        ) {
            throw new RuntimeException('IdP launch RelayState was not preserved');
        }
    }

    /**
     * Exceed Chromium's default-cookie POST grace period before returning from the IdP.
     *
     * @When /^I wait beyond the cross-site cookie grace period$/
     */
    public function age_cookies(): void {
        $this->getSession()->wait(125000);
    }
    /**
     * Follow the real, session-key-bearing Moodle logout link, including authentication hooks.
     *
     * @When /^I log out through Moodle$/
     */
    public function real_logout(): void {
        $link = $this->getSession()->getPage()->find('css', 'a[href*="/login/logout.php"]');
        if ($link === null) {
            throw new RuntimeException('No normal logout link');
        }
        $this->getSession()->visit($link->getAttribute('href'));
        $this->getSession()->visit('https://sp.saml.test/login/index.php?saml=off');
        if ($this->getSession()->getPage()->find('css', '#username') === null) {
            throw new RuntimeException('Moodle session was not invalidated');
        }
    }

    /**
     * Authenticate an independent administrator with the real password form.
     *
     * @param string $username Synthetic local administrator.
     * @When /^I authenticate local administrator "(localone|localtwo)"$/
     */
    public function local_login(string $username): void {
        $this->getSession()->visit('https://sp.saml.test/login/index.php?saml=off');
        $this->wait_for_pending_js();
        $this->execute('behat_forms::i_set_the_field_to', ['username', $username]);
        $this->execute('behat_forms::i_set_the_field_to', ['password', 'Synthetic-pass-12!']);
        $this->execute('behat_forms::press_button', ['Log in']);
        $this->wait_for_pending_js();
    }

    /**
     * Select a new fictional account without profile attributes.
     *
     * @Given /^the Stellantis identity is a new account$/
     */
    public function new_account(): void {
        $path = '/var/www/data/saml12.json';
        $config = json_decode(file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
        $config['attributes']['uid'] = ['new123456789'];
        file_put_contents($path, json_encode($config, JSON_THROW_ON_ERROR));
    }

    /**
     * The no-reporting browser fixture cannot invent missing profile values or grants.
     *
     * @Then /^the new Stellantis account requires profile completion$/
     */
    public function incomplete_profile(): void {
        global $DB;
        $user = $DB->get_record('user', ['username' => 'new123456789'], '*', MUST_EXIST);
        if ($user->firstname !== '' || $user->email !== '' || !user_not_fully_set_up($user)) {
            throw new RuntimeException('Expected incomplete new-user profile');
        }
        foreach (['role_assignments', 'user_enrolments', 'groups_members'] as $table) {
            if ($DB->record_exists($table, ['userid' => $user->id])) {
                throw new RuntimeException('Unexpected new-account grant');
            }
        }
    }
}
