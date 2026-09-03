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
        @unlink($CFG->dataroot . '/saml2/metadata.pending.json.activating');
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

    public function test_upgrade_moves_file_backed_pending_authority_into_shared_moodle_storage(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('version', 2026090300, 'auth_saml2');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new \auth_saml2\metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new \auth_saml2\idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'upgradePendingCertificate=', $xml);
        self::assertSame(
            \auth_saml2\metadata_trust_manager::PENDING,
            $manager->review($changed, (new \auth_saml2\idp_parser())->parse($changed))
        );
        $payload = $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'pending']);
        $DB->delete_records('auth_saml2_truststate', ['name' => 'pending']);
        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $path = $directory . '/metadata.pending.json';
        file_put_contents($path, $payload);

        self::assertTrue(\xmldb_auth_saml2_upgrade(2026090300));

        self::assertSame($payload, $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'pending']));
        self::assertFalse(get_config('auth_saml2', 'metadatapending'));
        self::assertFileDoesNotExist($path);
    }

    public function test_upgrade_quarantines_ambiguous_legacy_activating_marker(): void {
        global $CFG, $DB;

        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('version', 2026090300, 'auth_saml2');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'ambiguousUpgradeCertificate=', $xml);
        $manager->review($changed, (new idp_parser())->parse($changed));
        $payload = $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'pending']);
        $DB->delete_records('auth_saml2_truststate', ['name' => 'pending']);
        $path = $CFG->dataroot . '/saml2/metadata.pending.json.activating';
        make_writable_directory(dirname($path));
        file_put_contents($path, $payload);

        $this->expectException(\moodle_exception::class);
        try {
            \xmldb_auth_saml2_upgrade(2026090300);
        } finally {
            self::assertFileExists($path);
            self::assertFalse((new metadata_trust_manager())->has_pending());
        }
    }

    public function test_upgrade_retires_provably_committed_legacy_activating_marker(): void {
        global $CFG, $DB;

        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('version', 2026090300, 'auth_saml2');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'committedUpgradeCertificate=', $xml);
        $manager->review($changed, (new idp_parser())->parse($changed));
        $payload = $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'pending']);
        $decoded = json_decode($payload, true);
        $DB->delete_records('auth_saml2_truststate', ['name' => 'pending']);
        set_config('idpmetadata', $decoded['configvalue'], 'auth_saml2');
        set_config('metadataapproved', json_encode($decoded['descriptor']), 'auth_saml2');
        $this->existing_live_file('xml', $decoded['idps'][0]['xml']);
        $path = $CFG->dataroot . '/saml2/metadata.pending.json.activating';
        make_writable_directory(dirname($path));
        file_put_contents($path, $payload);

        self::assertTrue(\xmldb_auth_saml2_upgrade(2026090300));

        self::assertFileDoesNotExist($path);
        self::assertFalse((new metadata_trust_manager())->has_pending());
    }

    public function test_upgrade_quarantines_partial_legacy_activating_marker(): void {
        global $CFG, $DB;

        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('version', 2026090300, 'auth_saml2');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'partialUpgradeCertificate=', $xml);
        $manager->review($changed, (new idp_parser())->parse($changed));
        $payload = $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'pending']);
        $DB->delete_records('auth_saml2_truststate', ['name' => 'pending']);
        $this->existing_live_file('xml', $changed);
        $path = $CFG->dataroot . '/saml2/metadata.pending.json.activating';
        file_put_contents($path, $payload);

        $this->expectException(\moodle_exception::class);
        try {
            \xmldb_auth_saml2_upgrade(2026090300);
        } finally {
            self::assertFileExists($path);
            self::assertSame($xml, get_config('auth_saml2', 'idpmetadata'));
            self::assertFalse((new metadata_trust_manager())->has_pending());
        }
    }

    public function test_upgrade_moves_cached_trust_payloads_to_dedicated_storage(): void {
        global $DB;

        set_config('version', 2026090301, 'auth_saml2');
        $DB->delete_records('auth_saml2_truststate');
        $pending = json_encode(['kind' => 'pending', 'bounded' => true]);
        $journal = json_encode(['kind' => 'activation', 'bounded' => true]);
        set_config('metadatapending', $pending, 'auth_saml2');
        set_config('metadataactivationjournal', $journal, 'auth_saml2');

        self::assertTrue(\xmldb_auth_saml2_upgrade(2026090301));

        self::assertSame($pending, $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'pending']));
        self::assertSame($journal, $DB->get_field('auth_saml2_truststate', 'value', ['name' => 'activation']));
        self::assertFalse(get_config('auth_saml2', 'metadatapending'));
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_auth_bootstrap_tolerates_pre_schema_upgrade_then_upgrade_creates_state_table(): void {
        global $CFG, $DB;

        $dbman = $DB->get_manager();
        $table = new \xmldb_table('auth_saml2_truststate');
        $dbman->drop_table($table);
        set_config('version', 2026090301, 'auth_saml2');
        set_config('idpmetadata', '', 'auth_saml2');
        set_config('metadataactivationjournal', json_encode([
            'state' => 'prepared',
            'proposalfingerprint' => hash('sha256', 'legacy recovery'),
            'requirespending' => false,
            'clearpending' => true,
            'configfingerprint' => hash('sha256', ''),
            'descriptorfingerprint' => hash('sha256', 'descriptor'),
            'files' => [],
        ]), 'auth_saml2');
        require_once($CFG->dirroot . '/auth/saml2/auth.php');

        new \auth_plugin_saml2();
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
        self::assertTrue(\xmldb_auth_saml2_upgrade(2026090301));

        self::assertTrue($dbman->table_exists($table));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('legacy_private_key_modes')]
    public function test_upgrade_removes_unsafe_legacy_private_key_exposure_without_weakening_locked_modes(
        int $legacymode,
        int $expectedmode
    ): void {
        global $CFG;

        set_config('version', 2026090303, 'auth_saml2');
        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $directorymode = fileperms($directory) & 07777;
        $key = $directory . '/' . (new \moodle_url($CFG->wwwroot))->get_host() . '.pem';
        file_put_contents($key, 'legacy private key');
        chmod($key, $legacymode);
        $owner = fileowner($key);
        $group = filegroup($key);

        self::assertTrue(\xmldb_auth_saml2_upgrade(2026090303));

        clearstatcache(true, $key);
        self::assertSame('legacy private key', file_get_contents($key));
        self::assertSame($expectedmode, fileperms($key) & 0777);
        self::assertSame($owner, fileowner($key));
        self::assertSame($group, filegroup($key));
        self::assertSame($directorymode, fileperms($directory) & 07777);
    }

    /**
     * Legacy private-key modes and their safe upgraded forms.
     *
     * @return array<string, array{int, int}>
     */
    public static function legacy_private_key_modes(): array {
        return [
            'world-readable conventional mode' => [0644, 0600],
            'world-writable permissive mode' => [0666, 0600],
            'owner-only locked mode' => [0400, 0400],
            'explicit group-readable locked mode' => [0440, 0440],
        ];
    }
}
