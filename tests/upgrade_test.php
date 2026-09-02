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
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

namespace auth_saml2;

/**
 * Tests for static metadata trust upgrades.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversFunction('xmldb_auth_saml2_upgrade')]
final class upgrade_test extends \advanced_testcase {
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        require_once($CFG->libdir . '/adminlib.php');
        require_once($CFG->libdir . '/upgradelib.php');
        require_once($CFG->dirroot . '/auth/saml2/db/upgrade.php');
        @unlink($CFG->dataroot . '/saml2/metadata.pending.json');
    }

    public function test_new_install_default_disables_metadata_refresh(): void {
        $this->setAdminUser();
        $adminroot = \admin_get_root(true, true);
        $page = $adminroot->locate('authsettingsaml2');
        $setting = $page->settings->auth_saml2idpmetadatarefresh ?? null;

        self::assertInstanceOf(\admin_setting_configselect::class, $setting);
        self::assertSame(0, $setting->get_defaultsetting());
    }

    public function test_upgrade_preserves_inline_trust_and_disables_refresh_without_fetching(): void {
        global $CFG, $DB;

        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('version', 2026082900, 'auth_saml2');
        set_config('idpmetadata', $xml, 'auth_saml2');
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        unset_config('metadataapproved', 'auth_saml2');
        $record = $this->existing_idp('xml');
        $livefile = $this->existing_live_file('xml', $xml);
        $livehash = hash_file('sha256', $livefile);

        self::assertTrue(\xmldb_auth_saml2_upgrade(2026082900));

        self::assertSame($xml, get_config('auth_saml2', 'idpmetadata'));
        self::assertSame('0', get_config('auth_saml2', 'idpmetadatarefresh'));
        self::assertNotFalse(get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($record, $DB->get_record('auth_saml2_idps', ['id' => $record->id], '*', MUST_EXIST));
        self::assertSame($livehash, hash_file('sha256', $livefile));
        self::assertFalse((new metadata_trust_manager())->has_pending());
    }

    public function test_upgrade_preserves_intentionally_remote_install_and_refresh_choice(): void {
        global $DB;

        $url = 'https://idp.example.test/metadata';
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('version', 2026082900, 'auth_saml2');
        set_config('idpmetadata', $url, 'auth_saml2');
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        unset_config('metadataapproved', 'auth_saml2');
        $record = $this->existing_idp($url);
        $livefile = $this->existing_live_file($url, $xml);
        $livehash = hash_file('sha256', $livefile);

        self::assertTrue(\xmldb_auth_saml2_upgrade(2026082900));

        self::assertSame($url, get_config('auth_saml2', 'idpmetadata'));
        self::assertSame('1', get_config('auth_saml2', 'idpmetadatarefresh'));
        self::assertFalse(get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($record, $DB->get_record('auth_saml2_idps', ['id' => $record->id], '*', MUST_EXIST));
        self::assertSame($livehash, hash_file('sha256', $livefile));
        self::assertFalse((new metadata_trust_manager())->has_pending());
    }

    /**
     * Create a representative active legacy IdP record.
     *
     * @param string $source Metadata source.
     * @return \stdClass
     */
    private function existing_idp(string $source): \stdClass {
        global $DB;

        $record = (object) [
            'metadataurl' => $source,
            'entityid' => 'https://idp.example.org/idp/shibboleth',
            'activeidp' => 1,
            'defaultidp' => 1,
            'adminidp' => 1,
            'defaultname' => 'Preserved name',
            'displayname' => 'Preserved override',
            'logo' => 'https://idp.example.org/logo.png',
            'alias' => 'preserved',
            'whitelist' => '192.0.2.1',
        ];
        $record->id = $DB->insert_record('auth_saml2_idps', $record);
        return $record;
    }

    /**
     * Create a representative legacy live metadata file.
     *
     * @param string $source Metadata source.
     * @param string $xml Metadata XML.
     * @return string
     */
    private function existing_live_file(string $source, string $xml): string {
        global $CFG;

        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $file = $directory . '/' . md5($source) . '.idp.xml';
        file_put_contents($file, $xml);
        return $file;
    }
}
