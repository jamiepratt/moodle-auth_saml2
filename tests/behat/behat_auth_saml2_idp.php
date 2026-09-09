<?php
// This file is part of Moodle - http://moodle.org/
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
 * Synthetic Moodle-as-IdP browser journeys.
 *
 * @package auth_saml2
 * @copyright 2026 Shipmate
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_auth_saml2_idp extends behat_base {
    /** @var string Captured browser response, containing synthetic data only. */
    private string $idpresponse = '';

    /**
     * Configure only the disposable IdP and its local assertion receiver.
     *
     * @param string $mode Registration state.
     * @Given /^the Moodle IdP registration is "(approved|legacy|disabled)" +\# auth_saml2$/
     */
    public function configure_registration(string $mode): void {
        global $CFG;
        $acs = $CFG->wwwroot . '/auth/saml2/tests/fixtures/mocksp/acs.php';
        set_config('moodleidpenabled', $mode === 'disabled' ? 0 : 1, 'auth_saml2');
        set_config('moodleidpsplist', 'urn:shipmate:test:sp' . ($mode === 'approved' ? ' ' . $acs : ''), 'auth_saml2');
        set_config('mocksp_received', 0, 'auth_saml2');
    }

    /**
     * Send a browser AuthnRequest and retain the resulting response.
     *
     * @param string $target Approved or attacker-controlled destination.
     * @When /^I send a synthetic Moodle IdP request to the "(approved|attacker)" ACS +\# auth_saml2$/
     */
    public function send_request(string $target): void {
        global $CFG;
        $acs = $CFG->wwwroot . '/auth/saml2/tests/fixtures/mocksp/acs.php';
        if ($target === 'attacker') {
            $acs .= '?attacker=1';
        }
        $instant = gmdate('Y-m-d\\TH:i:s\\Z');
        $endpoint = $CFG->wwwroot . '/auth/saml2/idp/sso.php';
        $xml = '<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_browser_request" Version="2.0"' .
            ' IssueInstant="' . $instant . '" Destination="' . $endpoint . '" AssertionConsumerServiceURL="' . $acs . '">' .
            '<s:Issuer xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion">urn:shipmate:test:sp</s:Issuer></p:AuthnRequest>';
        $this->getSession()->visit($endpoint . '?SAMLRequest=' . urlencode(base64_encode(gzdeflate($xml))));
        $this->spin(function (): bool {
            return $this->getSession()->getPage()->find('css', 'form#frog') === null;
        });
        $this->idpresponse = $this->getSession()->getPage()->getContent();
        $this->getSession()->visit($this->locate_path('/'));
    }

    /**
     * Read the IdP metadata from its public route.
     *
     * @When /^I request the Moodle IdP metadata +\# auth_saml2$/
     */
    public function request_metadata(): void {
        $this->getSession()->visit($this->locate_path('/auth/saml2/idp/metadata.php'));
        $this->idpresponse = $this->getSession()->getPage()->getContent();
        $this->getSession()->visit($this->locate_path('/'));
    }

    /**
     * Assert that an untrusted receiver got no response, even a malformed one.
     *
     * @param int $expected Number of assertion POSTs.
     * @Then /^the synthetic SP should have received (\d+) assertions +\# auth_saml2$/
     */
    public function assert_received(int $expected): void {
        global $DB;
        $received = (int) $DB->get_field('config_plugins', 'value', ['plugin' => 'auth_saml2', 'name' => 'mocksp_received']);
        if ($expected === 0 && str_contains($this->idpresponse, 'name="SAMLResponse"')) {
            throw new \Behat\Mink\Exception\ExpectationException(
                'A refused request emitted an assertion form.',
                $this->getSession()
            );
        }
        if ($received !== $expected) {
            throw new \Behat\Mink\Exception\ExpectationException(
                "Expected {$expected} assertion POSTs, received {$received}.",
                $this->getSession()
            );
        }
    }

    /**
     * Check a safe message in the captured browser response.
     *
     * @param string $expected Response message.
     * @Then /^the Moodle IdP response should contain "([^"]*)" +\# auth_saml2$/
     */
    public function assert_response(string $expected): void {
        if (!str_contains($this->idpresponse, $expected)) {
            throw new \Behat\Mink\Exception\ExpectationException('Missing IdP response message: ' . $expected, $this->getSession());
        }
    }
}
