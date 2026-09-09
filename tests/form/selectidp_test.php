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

namespace auth_saml2\form;

/**
 * Tests metadata presentation on IdP forms.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(selectidp_buttons::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(selectidp_dropdown::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(availableidps::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(testidpselect::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(\auth_saml2\output\idp_logo::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(\auth_saml2\auth::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(\auth_saml2\admin\setting_idpmetadata::class)]
final class selectidp_test extends \advanced_testcase {
    /**
     * Names and attribute values remain data in rendered buttons.
     */
    public function test_button_metadata_is_rendered_as_data(): void {
        $this->resetAfterTest();
        $name = '<span id="metadata-name">Zażółć & 船</span>';
        $entityid = 'entity" data-metadata="injected';
        $logo = 'https://idp.example.test/logo.png?label=" data-metadata="injected';
        $form = new selectidp_buttons(null, [
            'metadataentities' => ['source' => [$entityid => (object) ['name' => $name, 'logo' => $logo]]],
            'storedchoiceidp' => '',
            'wants' => '/',
        ]);
        $document = new \DOMDocument();
        @$document->loadHTML('<?xml encoding="UTF-8">' . $form->render());
        $xpath = new \DOMXPath($document);
        $button = $xpath->query('//button[@name="idp"]')->item(0);

        self::assertSame($name, trim($button->textContent));
        self::assertSame($entityid, $button->getAttribute('value'));
        self::assertSame(0, $xpath->query('//*[@data-metadata or @id="metadata-name"]')->length);
        self::assertSame($logo, rawurldecode($xpath->query('//button/img')->item(0)->getAttribute('src')));
    }
    /**
     * The actual selector input retains every provider and promotes the remembered one.
     */
    public function test_selector_accepts_authentication_provider_list_and_remembers_choice(): void {
        $this->resetAfterTest();
        $generator = $this->getDataGenerator()->get_plugin_generator('auth_saml2');
        $first = $generator->create_idp_entity(['defaultname' => 'First 船']);
        $second = $generator->create_idp_entity(['defaultname' => 'Remembered Zażółć']);
        $providers = get_auth_plugin('saml2')->metadataentities;
        $remembered = md5($second->entityid);
        $form = new selectidp_buttons(null, [
            'metadataentities' => $providers,
            'storedchoiceidp' => $remembered,
            'wants' => '/',
        ]);
        $document = new \DOMDocument();
        @$document->loadHTML('<?xml encoding="UTF-8">' . $form->render());
        $xpath = new \DOMXPath($document);
        $buttons = $xpath->query('//button[@name="idp"]');

        self::assertSame(2, $buttons->length);
        self::assertSame($remembered, $buttons->item(0)->getAttribute('value'));
        self::assertSame('Remembered Zażółć', trim($buttons->item(0)->textContent));
        self::assertStringContainsString('rememberedidp', $buttons->item(0)->getAttribute('class'));
        self::assertSame(md5($first->entityid), $buttons->item(1)->getAttribute('value'));
        self::assertSame('First 船', trim($buttons->item(1)->textContent));
    }

    /**
     * Only HTTP(S) logos reach either login surface.
     *
     * @param string|null $logo Metadata URL.
     * @param bool $allowed Whether the image may be rendered.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('logo_urls')]
    public function test_logo_schemes_on_login_surfaces(?string $logo, bool $allowed): void {
        $this->resetAfterTest();
        $this->getDataGenerator()->get_plugin_generator('auth_saml2')->create_idp_entity(['logo' => $logo]);
        $auth = get_auth_plugin('saml2');
        $form = new selectidp_buttons(null, [
            'metadataentities' => $auth->metadataentities,
            'storedchoiceidp' => '',
            'wants' => '/',
        ]);
        $document = new \DOMDocument();
        @$document->loadHTML($form->render());
        $xpath = new \DOMXPath($document);
        $images = $xpath->query('//button[@name="idp"]/img');
        self::assertSame($allowed ? 1 : 0, $images->length);
        $provider = $auth->loginpage_idp_list('/')[0];
        if ($allowed) {
            self::assertSame($logo, $images->item(0)->getAttribute('src'));
            self::assertSame($logo, $provider['iconurl']->out(false));
        } else {
            self::assertNull($provider['iconurl']);
            self::assertInstanceOf(\pix_icon::class, $provider['icon']);
        }
    }

    /**
     * Metadata logo URL scheme cases.
     *
     * @return array
     */
    public static function logo_urls(): array {
        return [
            'https' => ['https://idp.example.test/logo.png?one=1&two=2', true],
            'http' => ['http://idp.example.test/logo.png', true],
            'javascript' => ['javascript:alert(1)', false],
            'mixed case script' => ['JaVaScRiPt:alert(1)', false],
            'data' => ['data:image/svg+xml,<svg onload="alert(1)"/>', false],
            'file' => ['file:///tmp/logo.png', false],
            'protocol relative' => ['//idp.example.test/logo.png', false],
            'relative' => ['/logo.png', false],
            'missing host' => ['https:///logo.png', false],
            'empty' => ['', false],
            'absent' => [null, false],
        ];
    }

    /**
     * Administrator labels and generated field attributes keep metadata inert.
     */
    public function test_administrator_metadata_labels_are_text(): void {
        $this->resetAfterTest();
        $name = '<span id="metadata-name">Zażółć & 船</span>';
        $entityid = 'https://idp.example.test/<span id="metadata-entity">entity</span>';
        $source = 'https://metadata.example.test/" data-metadata="injected';
        $key = 'entity" data-metadata="injected';
        $form = new availableidps(null, ['metadataentities' => [$source => [$key => [
            'name' => $name,
            'entityid' => $entityid,
            'defaultname' => $name,
        ]]]]);
        $document = new \DOMDocument();
        @$document->loadHTML('<?xml encoding="UTF-8">' . $form->render());
        $xpath = new \DOMXPath($document);

        self::assertSame(0, $xpath->query('//*[@id="metadata-name" or @id="metadata-entity" or @data-metadata]')->length);
        self::assertStringContainsString($name, $document->textContent);
        self::assertStringContainsString($entityid, $document->textContent);
        $input = $xpath->query('//input[@placeholder]')->item(0);
        self::assertSame($name, $input->getAttribute('placeholder'));
        self::assertSame('metadataentities[' . $source . '][' . $key . '][displayname]', $input->getAttribute('name'));
    }

    /**
     * Dropdown options preserve literal names, values and remembered selection.
     */
    public function test_dropdown_metadata_and_remembered_selection(): void {
        $this->resetAfterTest();
        $name = '<span id="metadata-name">Zażółć & 船</span>';
        $entityid = 'entity" data-metadata="injected';
        $form = new selectidp_dropdown(null, [
            'metadataentities' => ['first' => (object) ['name' => 'First'], $entityid => (object) ['name' => $name]],
            'wants' => '/',
            'idpname' => $name,
        ]);
        $form->set_data(['idp' => $entityid, 'rememberidp' => 1]);
        $document = new \DOMDocument();
        @$document->loadHTML('<?xml encoding="UTF-8">' . $form->render());
        $xpath = new \DOMXPath($document);
        $selected = $xpath->query('//select[@name="idp"]/option[@selected]')->item(0);
        self::assertSame($entityid, $selected->getAttribute('value'));
        self::assertSame($name, $selected->textContent);
        self::assertSame(0, $xpath->query('//*[@id="metadata-name" or @data-metadata]')->length);
        self::assertSame($name, $xpath->query('//input[@name="login"]')->item(0)->getAttribute('value'));
    }

    /**
     * Display-only refresh stays automatic and inert without changing approved trust.
     */
    public function test_refreshed_display_metadata_is_inert_and_preserves_trust(): void {
        global $CFG, $DB;
        require_once($CFG->dirroot . '/auth/saml2/locallib.php');
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/../fixtures/metadata.xml');
        $source = 'https://metadata.example.test/idp.xml';
        $setting = new \auth_saml2\admin\setting_idpmetadata(static function () use (&$xml): string {
            return $xml;
        });
        self::assertSame('', $setting->write_setting($source));
        $approved = get_config('auth_saml2', 'metadataapproved');
        $name = '<span id="metadata-name">Zażółć & 船</span>';
        $logo = 'data:image/svg+xml,<svg onload="void(0)"/>';
        $xml = str_replace('Example.com test IDP', s($name), $xml);
        $xml = str_replace('</mdui:UIInfo>', '<mdui:Logo>' . s($logo) . '</mdui:Logo></mdui:UIInfo>', $xml);
        self::assertSame('', $setting->write_setting($source));
        $manager = new \auth_saml2\metadata_trust_manager();
        self::assertFalse($manager->has_pending());
        self::assertSame($approved, get_config('auth_saml2', 'metadataapproved'));
        $record = $DB->get_record('auth_saml2_idps', ['metadataurl' => $source], '*', MUST_EXIST);
        self::assertSame($name, $record->defaultname);
        self::assertSame($logo, $record->logo);
        $form = new selectidp_buttons(null, [
            'metadataentities' => auth_saml2_get_idps(),
            'storedchoiceidp' => md5($record->entityid),
            'wants' => '/',
        ]);
        $document = new \DOMDocument();
        @$document->loadHTML('<?xml encoding="UTF-8">' . $form->render());
        $xpath = new \DOMXPath($document);
        self::assertSame($name, trim($xpath->query('//button[@name="idp"]')->item(0)->textContent));
        self::assertSame(0, $xpath->query('//button/img | //*[@id="metadata-name"]')->length);
        self::assertSame(1, $xpath->query('//button[@name="idp"]')->length);
        $activefile = $CFG->dataroot . '/saml2/' . md5($source) . '.idp.xml';
        self::assertSame($xml, file_get_contents($activefile));

        // A security change on the same source still requires approval and leaves active XML intact.
        $active = $xml;
        $xml = str_replace('/profile/SAML2/Redirect/SSO', '/profile/SAML2/Redirect/changed', $xml);
        self::assertSame(get_string('idpmetadata_pendingapproval', 'auth_saml2'), $setting->write_setting($source));
        self::assertTrue($manager->has_pending());
        self::assertTrue($manager->get_pending_summary()['endpoints']);
        self::assertSame($approved, get_config('auth_saml2', 'metadataapproved'));
        self::assertSame($active, file_get_contents($activefile));
    }

    /**
     * Administrator self-test selectors also display source and name as text.
     */
    public function test_selftest_selector_metadata_is_text(): void {
        $this->resetAfterTest();
        $name = '<span id="metadata-name">Zażółć & 船</span>';
        $source = '<span id="metadata-source">https://metadata.example.test/</span>';
        $form = new testidpselect(null, ['metadataentities' => [(object) [
            'name' => $name,
            'metadataurl' => $source,
            'md5entityid' => 'provider',
        ]]]);
        $document = new \DOMDocument();
        @$document->loadHTML('<?xml encoding="UTF-8">' . $form->render());
        $xpath = new \DOMXPath($document);
        foreach (['idp', 'idplogout'] as $field) {
            $option = $xpath->query('//select[@name="' . $field . '"]/option')->item(0);
            self::assertSame($source . ' (' . $name . ')', $option->textContent);
            self::assertSame('provider', $option->getAttribute('value'));
        }
        self::assertSame(0, $xpath->query('//*[@id="metadata-name" or @id="metadata-source"]')->length);
    }
}
