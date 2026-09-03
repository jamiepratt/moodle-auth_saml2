<?php
// This file is part of SAML2 Authentication Plugin
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

namespace auth_saml2;

use auth_saml2\admin\setting_idpmetadata;
use auth_saml2\admin\setting_idpmetadata_exception;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * Test setting idp Metadata.
 *
 * @package     auth_saml2
 * @author      Daniel Thee Roperto <daniel.roperto@catalyst-au.net>
 * @copyright   2018 Catalyst IT Australia {@link http://www.catalyst-au.net}
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(setting_idpmetadata::class)]
final class setting_idpmetadata_test extends \advanced_testcase {
    /** @var setting_idpmetadata */
    private static $config;

    protected function setUp(): void {
        global $CFG;
        parent::setUp();
        @unlink($CFG->dataroot . '/saml2/metadata.pending.json');
        self::$config = new setting_idpmetadata();
    }

    public function test_it_validates_the_xml(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        $data = self::$config->validate($xml);
        self::assertTrue($data);
    }

    public function test_it_rejects_metadata_without_an_idp_descriptor(): void {
        $this->resetAfterTest();
        $xml = '<?xml version="1.0"?><md:EntitiesDescriptor ' .
            'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" />';

        self::assertSame(get_string('idpmetadata_invalid', 'auth_saml2'), self::$config->validate($xml));
    }

    public function test_it_rejects_an_empty_entity_id(): void {
        $this->resetAfterTest();
        $xml = <<<'XML'
            <md:EntityDescriptor entityID="" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" />
            </md:EntityDescriptor>
            XML;

        self::assertSame(get_string('idpmetadata_invalid', 'auth_saml2'), self::$config->validate($xml));
    }

    public function test_it_saves_all_idp_information(): void {
        global $CFG;

        $this->resetAfterTest();

        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::$config->write_setting($xml);
        $actual = get_config('auth_saml2');

        self::assertSame($xml, $actual->idpmetadata, 'Invalid config metadata.');

        $metadataidps = auth_saml2_get_idps();
        foreach ($metadataidps as $metadataurl => $idps) {
            self::assertSame('xml', $metadataurl);

            foreach ($idps as $idp) {
                self::assertSame('https://idp.example.org/idp/shibboleth', $idp->entityid);
                self::assertSame('Example.com test IDP', $idp->name);
            }
        }

        $file = md5('xml') . '.idp.xml';
        $file = "{$CFG->dataroot}/saml2/{$file}";
        self::assertFileExists($file);
        $actual = file_get_contents($file);
        self::assertSame(trim($xml), $actual, "Invalid saved XML contents for: {$file}");
    }

    public function test_it_does_not_activate_a_changed_signing_key_before_approval(): void {
        global $CFG;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertSame('', self::$config->write_setting($xml));
        $file = $CFG->dataroot . '/saml2/' . md5('xml') . '.idp.xml';
        $livehash = hash_file('sha256', $file);
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'differentSigningCertificate=', $xml);

        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($changed)
        );
        self::assertSame($xml, get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($livehash, hash_file('sha256', $file));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('security_relevant_changes')]
    public function test_security_relevant_change_is_staged_without_altering_the_active_checkpoint(
        string $change,
        string $summaryfield
    ): void {
        global $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $setting = self::$config;
        if ($change === 'signingkeys') {
            $proposal = str_replace('q1og9SGCUU2yRL1tC+Y=', 'replacementSigningCertificate=', $xml);
        } else if ($change === 'entities') {
            $proposal = str_replace(
                'entityID="https://idp.example.org/idp/shibboleth"',
                'entityID="https://replacement.example.org/idp/shibboleth"',
                $xml
            );
        } else if ($change === 'endpoints') {
            $proposal = str_replace(
                'https://idp.example.org/idp/profile/SAML2/Redirect/SSO',
                'https://replacement.example.org/idp/profile/SAML2/Redirect/SSO',
                $xml
            );
        } else {
            $proposal = 'https://idp.example.test/metadata';
            $setting = new setting_idpmetadata(static fn(): string => $xml);
        }

        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            $setting->write_setting($proposal)
        );

        $manager = new metadata_trust_manager();
        self::assertTrue($manager->get_pending_summary()[$summaryfield]);
        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
    }

    /**
     * Security-relevant metadata changes.
     *
     * @return array
     */
    public static function security_relevant_changes(): array {
        return [
            'signing key' => ['signingkeys', 'signingkeys'],
            'entity ID' => ['entities', 'entities'],
            'security endpoint' => ['endpoints', 'endpoints'],
            'metadata source' => ['sources', 'sources'],
        ];
    }

    public function test_write_failure_preserves_the_complete_active_trust_checkpoint(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $livefile = $CFG->dataroot . '/saml2/' . md5('xml') . '.idp.xml';
        chmod($livefile, 0400);
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $changed = str_replace('Example.com test IDP', 'Changed display name', $xml);
        $setting = new setting_idpmetadata(null, static function (string $file): void {
            file_put_contents($file, 'partially written metadata');
            throw new setting_idpmetadata_exception(get_string('idpmetadata_writefailed', 'auth_saml2'));
        });

        self::assertSame(
            get_string('idpmetadata_writefailed', 'auth_saml2'),
            $setting->write_setting($changed)
        );

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertSame(hash('sha256', trim($xml)), hash_file('sha256', $livefile));
        clearstatcache(true, $livefile);
        self::assertSame(0400, fileperms($livefile) & 0777);
    }

    public function test_live_metadata_uses_the_secure_moodle_storage_identity_and_preserves_stricter_modes(): void {
        global $CFG;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertSame('', self::$config->write_setting($xml));
        $livefile = $CFG->dataroot . '/saml2/' . md5('xml') . '.idp.xml';
        clearstatcache(true, $livefile);
        self::assertSame(0640, fileperms($livefile) & 0777);
        self::assertSame(posix_geteuid(), fileowner($livefile));
        self::assertSame(filegroup(dirname($livefile)), filegroup($livefile));

        chmod($livefile, 0666);
        $changed = str_replace('Example.com test IDP', 'Hardened display name', $xml);
        self::assertEmpty(self::$config->write_setting($changed));

        clearstatcache(true, $livefile);
        self::assertSame(0640, fileperms($livefile) & 0777);

        chmod($livefile, 0400);
        $changed = str_replace('Hardened display name', 'Changed display name', $changed);
        self::assertEmpty(self::$config->write_setting($changed));

        clearstatcache(true, $livefile);
        self::assertSame(0400, fileperms($livefile) & 0777);
    }

    public function test_distinct_nonroot_writers_preserve_access_through_an_explicit_shared_group(): void {
        global $CFG;

        if (
            !function_exists('posix_geteuid') ||
            !function_exists('posix_seteuid') ||
            !function_exists('posix_setegid') ||
            posix_geteuid() !== 0
        ) {
            $this->markTestSkipped('Changing effective identities requires POSIX support and a root test process.');
        }

        $this->resetAfterTest();
        $originalgid = posix_getegid();
        $directory = $CFG->dataroot . '/saml2/shared-group-' . random_string(10);
        self::assertTrue(mkdir($directory, 02770, true));
        $sharedgid = 65534;
        self::assertTrue(chgrp($directory, $sharedgid));
        self::assertTrue(chmod($directory, 02770));
        $temporary = $directory . '/metadata.tmp';
        file_put_contents($temporary, 'shared metadata');
        self::assertTrue(chown($temporary, 34));
        self::assertTrue(chgrp($temporary, $sharedgid));
        $attributes = ['owner' => 33, 'group' => $sharedgid, 'mode' => 0640];
        $method = new \ReflectionMethod(setting_idpmetadata::class, 'apply_file_attributes');

        try {
            self::assertTrue(posix_setegid($sharedgid));
            self::assertTrue(posix_seteuid(34));
            self::assertTrue($method->invoke(self::$config, $temporary, $attributes));
        } finally {
            posix_seteuid(0);
            posix_setegid($originalgid);
        }

        clearstatcache(true, $temporary);
        self::assertSame(34, fileowner($temporary));
        self::assertSame($sharedgid, filegroup($temporary));
        self::assertSame(0640, fileperms($temporary) & 0777);
        try {
            self::assertTrue(posix_setegid($sharedgid));
            self::assertTrue(posix_seteuid(33));
            self::assertSame('shared metadata', file_get_contents($temporary));
        } finally {
            posix_seteuid(0);
            posix_setegid($originalgid);
        }
    }

    public function test_metadata_group_is_the_actual_setgid_directory_group(): void {
        global $CFG;

        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            $this->markTestSkipped('Selecting a synthetic group requires a root test process.');
        }
        $directory = $CFG->dataroot . '/saml2/group-selection-' . random_string(10);
        self::assertTrue(mkdir($directory, 02770, true));
        self::assertTrue(chgrp($directory, 65534));
        self::assertTrue(chmod($directory, 02770));
        $method = new \ReflectionMethod(setting_idpmetadata::class, 'metadata_storage_group');

        self::assertSame(65534, $method->invoke(self::$config, $directory));
    }

    public function test_distinct_nonroot_writer_activates_through_shared_setgid_directory(): void {
        global $CFG;

        if (
            !function_exists('posix_seteuid') ||
            !function_exists('posix_setegid') ||
            posix_geteuid() !== 0
        ) {
            $this->markTestSkipped('Changing effective identities requires a root POSIX test process.');
        }
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertSame('', self::$config->write_setting($xml));
        $directory = $CFG->dataroot . '/saml2';
        $livefile = $directory . '/' . md5('xml') . '.idp.xml';
        $sharedgid = 65534;
        self::assertTrue(chgrp($directory, $sharedgid));
        self::assertTrue(chmod($directory, 02770));
        self::assertTrue(chgrp($livefile, $sharedgid));
        self::assertTrue(chmod($livefile, 0640));
        $changed = str_replace('Example.com test IDP', 'Shared writer display name', $xml);
        $originalgid = posix_getegid();

        try {
            self::assertTrue(posix_setegid($sharedgid));
            self::assertTrue(posix_seteuid(34));
            $result = self::$config->write_setting($changed);
        } finally {
            posix_seteuid(0);
            posix_setegid($originalgid);
        }

        self::assertSame('', $result);
        clearstatcache(true, $livefile);
        self::assertSame(34, fileowner($livefile));
        self::assertSame($sharedgid, filegroup($livefile));
        try {
            self::assertTrue(posix_setegid($sharedgid));
            self::assertTrue(posix_seteuid(33));
            self::assertSame(trim($changed), file_get_contents($livefile));
        } finally {
            posix_seteuid(0);
            posix_setegid($originalgid);
        }
    }

    public function test_config_storage_failure_cannot_activate_validated_metadata(): void {
        global $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $changed = str_replace('Example.com test IDP', 'Validated but not stored', $xml);
        $setting = new setting_idpmetadata(null, null, static fn(): bool => false);

        self::assertSame(get_string('errorsetting', 'admin'), $setting->write_setting($changed));

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('failed_proposals')]
    public function test_failed_proposal_preserves_the_complete_active_trust_checkpoint(
        string $failure,
        string $proposal
    ): void {
        global $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $downloader = static function () use ($failure): string {
            if ($failure === 'tls') {
                throw new \moodle_exception('metadatafetchfailed', 'auth_saml2', '', 'certificate verify failed');
            }
            if ($failure === 'status') {
                throw new \moodle_exception('metadatafetchfailedstatus', 'auth_saml2', '', 503);
            }
            return '<not valid XML';
        };

        $error = (new setting_idpmetadata($downloader))->write_setting($proposal);

        self::assertNotSame('', $error);
        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertFalse((new metadata_trust_manager())->has_pending());
    }

    /**
     * Failed remote proposal types.
     *
     * @return array
     */
    public static function failed_proposals(): array {
        return [
            'TLS certificate failure' => ['tls', 'https://idp.example.test/metadata'],
            'HTTP response failure' => ['status', 'https://idp.example.test/metadata'],
            'invalid XML' => ['xml', 'https://idp.example.test/metadata'],
            'plain HTTP' => ['http', 'http://idp.example.test/metadata'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('approval_authorities')]
    public function test_authorised_owner_can_approve_and_activate_a_staged_rollover(string $authority): void {
        global $CFG;

        $this->resetAfterTest();
        $admin = get_admin();
        $this->setUser($admin);
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::$config->write_setting($xml);
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'approvedSigningCertificate=', $xml);
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($changed)
        );
        $manager = new metadata_trust_manager();
        $pendingfingerprint = $manager->get_pending_summary()['proposedfingerprint'];
        $approvalfingerprint = $manager->get_pending_fingerprint();

        $sink = $this->redirectEvents();
        self::$config->approve_pending($admin->id, $authority, true, $approvalfingerprint);
        $events = $sink->get_events();
        $sink->close();

        self::assertSame($changed, get_config('auth_saml2', 'idpmetadata'));
        $file = $CFG->dataroot . '/saml2/' . md5('xml') . '.idp.xml';
        self::assertSame(trim($changed), file_get_contents($file));
        self::assertFalse($manager->has_pending());
        $approved = json_decode(get_config('auth_saml2', 'metadataapproved'), true);
        self::assertSame($pendingfingerprint, $approved['fingerprint']);
        $approvalevents = array_values(array_filter(
            $events,
            static fn(\core\event\base $event): bool => $event instanceof event\metadata_change_approved
        ));
        self::assertCount(1, $approvalevents);
        self::assertSame($authority, $approvalevents[0]->other['authority']);
    }

    /**
     * Approval authorities that may activate staged metadata.
     *
     * @return array
     */
    public static function approval_authorities(): array {
        return [
            'service owner' => [metadata_trust_manager::AUTHORITY_OWNER],
            'emergency delegate' => [metadata_trust_manager::AUTHORITY_DELEGATE],
        ];
    }

    public function test_invalid_approval_authority_cannot_activate_staged_metadata(): void {
        global $CFG;

        $this->resetAfterTest();
        $this->setAdminUser();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::$config->write_setting($xml);
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'unapprovedSigningCertificate=', $xml);
        self::$config->validate($changed);
        $approvalfingerprint = (new metadata_trust_manager())->get_pending_fingerprint();
        $file = $CFG->dataroot . '/saml2/' . md5('xml') . '.idp.xml';

        try {
            self::$config->approve_pending(get_admin()->id, 'unauthorised', true, $approvalfingerprint);
            self::fail('Invalid authority must be rejected.');
        } catch (\invalid_parameter_exception $exception) {
            self::assertSame($xml, get_config('auth_saml2', 'idpmetadata'));
            self::assertSame(trim($xml), file_get_contents($file));
            self::assertTrue((new metadata_trust_manager())->has_pending());
        }
    }

    public function test_approval_requires_explicit_out_of_band_confirmation(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'unconfirmedSigningCertificate=', $xml);
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($changed)
        );
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];

        try {
            self::$config->approve_pending(
                get_admin()->id,
                metadata_trust_manager::AUTHORITY_OWNER,
                false,
                (new metadata_trust_manager())->get_pending_fingerprint()
            );
            self::fail('Activation must require explicit out-of-band confirmation.');
        } catch (\moodle_exception $exception) {
            self::assertSame(
                get_string('metadataapprovalconfirmationrequired', 'auth_saml2'),
                $exception->getMessage()
            );
        }

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertTrue((new metadata_trust_manager())->has_pending());
    }

    public function test_approval_rejects_a_pending_proposal_replaced_after_review(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $proposalareviewed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'reviewedSigningCertificate=', $xml);
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($proposalareviewed)
        );
        $manager = new metadata_trust_manager();
        $reviewedfingerprint = $manager->get_pending_fingerprint();
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];

        $proposalbreplacement = str_replace('q1og9SGCUU2yRL1tC+Y=', 'replacementSigningCertificate=', $xml);
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($proposalbreplacement)
        );

        try {
            self::$config->approve_pending(
                get_admin()->id,
                metadata_trust_manager::AUTHORITY_OWNER,
                true,
                $reviewedfingerprint
            );
            self::fail('Approval must be bound to the exact proposal that was reviewed.');
        } catch (\moodle_exception $exception) {
            self::assertStringContainsString('proposal', strtolower($exception->getMessage()));
        }

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertTrue($manager->has_pending());
        self::assertNotSame($reviewedfingerprint, $manager->get_pending_summary()['proposedfingerprint']);
    }

    public function test_user_without_site_configuration_capability_cannot_activate_metadata(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'unauthorisedSigningCertificate=', $xml);
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($changed)
        );
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $approvalfingerprint = (new metadata_trust_manager())->get_pending_fingerprint();
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        try {
            self::$config->approve_pending(
                $user->id,
                metadata_trust_manager::AUTHORITY_OWNER,
                true,
                $approvalfingerprint
            );
            self::fail('Site configuration capability must be required.');
        } catch (\required_capability_exception $exception) {
            self::assertStringContainsString('do not currently have permissions', $exception->getMessage());
        }

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertTrue((new metadata_trust_manager())->has_pending());
    }

    public function test_approved_rollover_write_failure_restores_active_trust_and_keeps_proposal(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'approvedButUnwritableCertificate=', $xml);
        $proposal = 'https://idp.example.test/rollover-metadata';
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            (new setting_idpmetadata(static fn(): string => $changed))->validate($proposal)
        );
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $setting = new setting_idpmetadata(null, static function (string $file): void {
            file_put_contents($file, 'partially written metadata');
            throw new setting_idpmetadata_exception(get_string('idpmetadata_writefailed', 'auth_saml2'));
        });

        try {
            $setting->approve_pending(
                get_admin()->id,
                metadata_trust_manager::AUTHORITY_OWNER,
                true,
                (new metadata_trust_manager())->get_pending_fingerprint()
            );
            self::fail('A failed live write must abort approved activation.');
        } catch (setting_idpmetadata_exception $exception) {
            self::assertSame(get_string('idpmetadata_writefailed', 'auth_saml2'), $exception->getMessage());
        }

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertTrue((new metadata_trust_manager())->has_pending());
    }

    public function test_approved_rollover_config_failure_restores_active_trust_and_keeps_proposal(): void {
        global $DB;

        $this->resetAfterTest();
        $this->setAdminUser();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'approvedButUnstoredCertificate=', $xml);
        self::assertSame(
            get_string('idpmetadata_pendingapproval', 'auth_saml2'),
            self::$config->validate($changed)
        );
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $setting = new setting_idpmetadata(null, null, static fn(): bool => false);

        try {
            $setting->approve_pending(
                get_admin()->id,
                metadata_trust_manager::AUTHORITY_OWNER,
                true,
                (new metadata_trust_manager())->get_pending_fingerprint()
            );
            self::fail('A failed approved configuration write must abort activation.');
        } catch (setting_idpmetadata_exception $exception) {
            self::assertSame(get_string('errorsetting', 'admin'), $exception->getMessage());
        }

        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertTrue((new metadata_trust_manager())->has_pending());
    }

    public function test_it_saves_all_idps_information_from_single_xml(): void {
        global $CFG;

        $this->resetAfterTest();

        $xml = file_get_contents(__DIR__ . '/fixtures/dualmetadata.xml');
        self::$config->write_setting($xml);
        $actual = get_config('auth_saml2');

        self::assertSame($xml, $actual->idpmetadata, 'Invalid config metadata.');

        $metadataidps = auth_saml2_get_idps();
        foreach ($metadataidps as $metadataurl => $idps) {
            self::assertSame('xml', $metadataurl);

            $idp1md5 = md5('https://idp1.example.org/idp/shibboleth');
            $idp2md5 = md5('https://idp2.example.org/idp/shibboleth');

            self::assertTrue(array_key_exists($idp1md5, $idps));
            self::assertTrue(array_key_exists($idp2md5, $idps));

            self::assertSame('First Test IDP', $idps[$idp1md5]->name);
            self::assertSame('Second Test IDP', $idps[$idp2md5]->name);
        }

        $file = md5("xml") . '.idp.xml';
        $file = "{$CFG->dataroot}/saml2/{$file}";
        self::assertFileExists($file);
        $actual = file_get_contents($file);
        self::assertSame(trim($xml), $actual, "Invalid saved XML contents for: {$file}");
    }

    public function test_it_allows_empty_values(): void {
        self::assertTrue(self::$config->validate(''), 'Validate empty string.');
        self::assertTrue(self::$config->validate('  '), ' Should trim spaces.');
        self::assertTrue(self::$config->validate("\n \n"), 'Should trim newlines.');
    }

    public function test_it_gets_idp_data_for_xml(): void {
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        $data = self::$config->get_idps_data($xml);
        self::assertCount(1, $data);
        $this->validate_idp_data_array($data);
    }

    public function test_it_gets_idp_data_for_two_urls(): void {
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        $config = new setting_idpmetadata(static function (string $url) use ($xml): string {
            return $xml;
        });

        $urls = "https://idp-one.invalid/metadata\nhttps://idp-two.invalid/metadata";
        $data = $config->get_idps_data($urls);

        self::assertCount(2, $data);
        $this->validate_idp_data_array($data);
    }

    public function test_it_rejects_http_metadata_before_downloading(): void {
        $this->resetAfterTest();
        $downloaded = false;
        $config = new setting_idpmetadata(static function (string $url) use (&$downloaded): string {
            $downloaded = true;
            return '';
        });

        $error = $config->validate('http://idp.example.test/metadata');

        self::assertSame(get_string('idpmetadata_httpsrequired', 'auth_saml2'), $error);
        self::assertFalse($downloaded);
    }

    public function test_oversized_remote_metadata_cannot_change_active_state(): void {
        global $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        self::assertEmpty(self::$config->write_setting($xml));
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'files' => $this->metadata_file_hashes(),
        ];
        $setting = new setting_idpmetadata(static function (): string {
            return str_repeat('x', metadata_fetcher::MAX_METADATA_BYTES + 1);
        });

        self::assertSame(
            get_string('metadatafetchtoolarge', 'auth_saml2'),
            $setting->write_setting('https://idp.example.test/oversized.xml')
        );
        self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
        self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
        self::assertSame($before['files'], $this->metadata_file_hashes());
        self::assertFalse((new metadata_trust_manager())->has_pending());
    }

    public function test_oversized_activation_journal_cannot_replace_live_metadata(): void {
        global $CFG;

        $this->resetAfterTest();
        unset_config('idpmetadata', 'auth_saml2');
        unset_config('metadataapproved', 'auth_saml2');
        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $largefile = $directory . '/oversized-snapshot.idp.xml';
        file_put_contents($largefile, str_repeat('x', metadata_trust_manager::MAX_JOURNAL_BYTES + 1));
        $beforehash = hash_file('sha256', $largefile);
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');

        self::assertSame(
            get_string('idpmetadata_pendingwritefailed', 'auth_saml2'),
            self::$config->write_setting($xml)
        );
        self::assertFalse(get_config('auth_saml2', 'idpmetadata'));
        self::assertFalse(get_config('auth_saml2', 'metadataapproved'));
        self::assertSame($beforehash, hash_file('sha256', $largefile));
    }

    public function test_it_returns_error_if_metadata_url_is_not_valid(): void {
        $config = new setting_idpmetadata(static function (string $url): string {
            throw new \moodle_exception('metadatafetchfailed', 'auth_saml2', '', $url);
        });
        $error = $config->validate('https://invalid.url.metadata.test');
        if (method_exists($this, 'assertStringContainsString')) {
            self::assertStringContainsString('Metadata fetch failed', $error);
            self::assertStringContainsString('invalid.url.metadata.test', $error);
        } else {
            // Maintains Support for Moodle 3.5 - remove when this branch does not support Moodle 3.5 anymore.
            self::assertContains('Metadata fetch failed', $error);
            self::assertContains('invalid.url.metadata.test', $error);
        }
    }

    /**
     * Validate idp data array.
     *
     * @param idp_data[] $idps
     */
    private function validate_idp_data_array($idps) {
        foreach ($idps as $idp) {
            self::assertInstanceOf(idp_data::class, $idp);
            self::assertNotNull($idp->get_rawxml());
        }
    }

    /**
     * Return hashes for every active metadata file.
     *
     * @return array
     */
    private function metadata_file_hashes(): array {
        global $CFG;

        $hashes = [];
        foreach (glob($CFG->dataroot . '/saml2/*.idp.xml') ?: [] as $file) {
            $hashes[basename($file)] = hash_file('sha256', $file);
        }
        ksort($hashes);
        return $hashes;
    }

    /**
     * Cleanup after all tests are executed.
     *
     * @return void
     */
    public static function tearDownAfterClass(): void {  // @codingStandardsIgnoreLine - ignore case of function.
        parent::tearDownAfterClass();
        if (self::$config) {
            self::$config = null;
        }
        libxml_clear_errors();
    }
}
