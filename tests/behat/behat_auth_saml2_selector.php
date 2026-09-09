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

use auth_saml2\admin\saml2_settings;
use auth_saml2\admin\setting_idpmetadata;
use Behat\Mink\Exception\ExpectationException;

require_once(__DIR__ . '/../../../../lib/behat/behat_base.php');

/**
 * Browser assertions for metadata presentation.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_auth_saml2_selector extends behat_base {
    /** @var string Inert HTML-like display name. */
    private const NAME = '<span id="saml-selector-name" data-saml-xss="1">Zażółć & 船</span>';

    /** @var string Inert HTML-like entity identifier. */
    private const ENTITY = 'https://idp.example.test/<span id="saml-selector-entity">entity</span>';

    /** @var string Normal Unicode provider label. */
    private const NORMAL = 'École Zażółć 船';

    /**
     * Refresh display-only data through the real metadata setting.
     *
     * @Given /^refreshed inert multi-IdP metadata is configured +\# auth_saml2$/
     */
    public function refreshed_inert_metadata_is_configured(): void {
        global $CFG, $DB;
        $document = new DOMDocument();
        $document->load(__DIR__ . '/../fixtures/dualmetadata.xml');
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xpath->registerNamespace('mdui', 'urn:oasis:names:tc:SAML:metadata:ui');
        $entities = $xpath->query('//md:EntityDescriptor');
        $entities->item(0)->setAttribute('entityID', self::ENTITY);
        foreach ($xpath->query('//*[@Location]') as $endpoint) {
            $endpoint->setAttribute('Location', $CFG->wwwroot . '/auth/saml2/tests/fixtures/mockidp/sso.php');
        }
        $setting = new setting_idpmetadata();
        if ($setting->write_setting($document->saveXML()) !== '') {
            throw new ExpectationException('Could not activate initial synthetic metadata.', $this->getSession());
        }
        $approved = get_config('auth_saml2', 'metadataapproved');
        $names = $xpath->query('//mdui:DisplayName');
        $names->item(0)->textContent = self::NAME;
        $names->item(1)->textContent = self::NORMAL;
        foreach ($xpath->query('//mdui:UIInfo') as $index => $info) {
            $logo = $document->createElementNS('urn:oasis:names:tc:SAML:metadata:ui', 'mdui:Logo');
            $logo->textContent = $index === 0
                ? 'data:image/svg+xml,<svg onload="void(0)"/>'
                : $CFG->wwwroot . '/pix/moodlelogo.png';
            $info->appendChild($logo);
        }
        if (
            $setting->write_setting($document->saveXML()) !== '' ||
            get_config('auth_saml2', 'metadataapproved') !== $approved ||
            (new \auth_saml2\metadata_trust_manager())->has_pending()
        ) {
            throw new ExpectationException('Display refresh changed trust approval.', $this->getSession());
        }
        $DB->set_field('auth_saml2_idps', 'activeidp', 1);
        set_config('duallogin', saml2_settings::OPTION_DUAL_LOGIN_YES, 'auth_saml2');
    }

    /**
     * Visit the unauthenticated selector after a passive attempt, without contacting an IdP.
     *
     * @param string $mode Selector style.
     * @When /^I visit the SAML (buttons|dropdown) selector +\# auth_saml2$/
     */
    public function visit_selector(string $mode): void {
        $value = $mode === 'buttons' ? saml2_settings::OPTION_MULTI_IDP_DISPLAY_BUTTONS
            : saml2_settings::OPTION_MULTI_IDP_DISPLAY_DROPDOWN;
        set_config('multiidpdisplay', $value, 'auth_saml2');
        $this->getSession()->visit($this->locate_path('/auth/saml2/selectidp.php?passive=0'));
    }

    /**
     * Inspect browser DOM and the ordinary local image after refresh.
     *
     * @Then /^the refreshed SAML buttons should contain only inert metadata +\# auth_saml2$/
     */
    public function buttons_are_inert(): void {
        $this->assert_inert();
        $page = $this->getSession()->getPage();
        $buttons = $page->findAll('css', 'button[name="idp"]');
        if (count($buttons) !== 2 || $buttons[0]->getText() !== self::NAME || $buttons[1]->getText() !== self::NORMAL) {
            throw new ExpectationException('Provider labels were not preserved as literal text.', $this->getSession());
        }
        if ($buttons[0]->find('css', 'img') !== null || $buttons[1]->find('css', 'img') === null) {
            throw new ExpectationException('Unsafe or normal logo handling changed.', $this->getSession());
        }
        $loaded = $this->getSession()->evaluateScript(
            'return document.querySelector("button[name=idp] img").naturalWidth > 0;'
        );
        if (!$loaded) {
            throw new ExpectationException('The ordinary local logo did not load.', $this->getSession());
        }
    }

    /**
     * Remember the normal provider using the public cookie format.
     *
     * @When /^I remember the normal SAML provider +\# auth_saml2$/
     */
    public function remember_normal_provider(): void {
        global $CFG;
        $this->getSession()->setCookie('MOODLEIDP1_' . $CFG->sessioncookie, md5('https://idp2.example.org/idp/shibboleth'));
    }

    /**
     * Verify one promoted button with the correct submission value.
     *
     * @Then /^the normal SAML provider should be remembered once +\# auth_saml2$/
     */
    public function normal_provider_is_remembered(): void {
        $this->assert_inert();
        $buttons = $this->getSession()->getPage()->findAll('css', 'button[name="idp"]');
        if (
            count($buttons) !== 2 || $buttons[0]->getText() !== self::NORMAL ||
            !$buttons[0]->hasClass('rememberedidp') ||
            $buttons[0]->getAttribute('value') !== md5('https://idp2.example.org/idp/shibboleth')
        ) {
            throw new ExpectationException('Remembered provider rendering changed.', $this->getSession());
        }
    }

    /**
     * Verify escaped dropdown text and selected remembered value.
     *
     * @Then /^the SAML dropdown should preserve metadata and selection +\# auth_saml2$/
     */
    public function dropdown_preserves_metadata(): void {
        $this->assert_inert();
        $page = $this->getSession()->getPage();
        $options = $page->findAll('css', 'select[name="idp"] option');
        $selected = $page->find('css', 'select[name="idp"]')->getValue();
        if (
            count($options) !== 2 || $options[0]->getText() !== self::NAME ||
            $options[1]->getText() !== self::NORMAL || $selected !== md5('https://idp2.example.org/idp/shibboleth')
        ) {
            throw new ExpectationException('Dropdown metadata or remembered selection changed.', $this->getSession());
        }
    }

    /**
     * Inspect metadata-derived administrator headings and source labels.
     *
     * @Then /^the SAML administrator labels should contain only inert metadata +\# auth_saml2$/
     */
    public function administrator_labels_are_inert(): void {
        $this->getSession()->visit($this->locate_path('/auth/saml2/availableidps.php'));
        $this->assert_inert();
        $text = $this->getSession()->getPage()->getText();
        foreach ([self::NAME, self::NORMAL, self::ENTITY] as $expected) {
            if (!str_contains($text, $expected)) {
                throw new ExpectationException('An administrator metadata label changed.', $this->getSession());
            }
        }
    }

    /**
     * Verify fixture markup never becomes a DOM element or attribute.
     */
    private function assert_inert(): void {
        if ($this->getSession()->getPage()->find('css', '#saml-selector-name, #saml-selector-entity, [data-saml-xss]') !== null) {
            throw new ExpectationException('Metadata became executable markup.', $this->getSession());
        }
    }
}
