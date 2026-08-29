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
 * Tests for IdP metadata trust decisions.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(metadata_trust_manager::class)]
final class metadata_trust_manager_test extends \advanced_testcase {
    protected function setUp(): void {
        global $CFG;
        parent::setUp();
        @unlink($CFG->dataroot . '/saml2/metadata.pending.json');
    }

    public function test_bootstrap_approves_existing_inline_metadata_without_replacing_it(): void {
        global $CFG;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');

        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $livefile = $directory . '/' . md5('xml') . '.idp.xml';
        file_put_contents($livefile, $xml);
        $beforehash = hash_file('sha256', $livefile);

        $idps = (new idp_parser())->parse($xml);
        $manager = new metadata_trust_manager();

        self::assertTrue($manager->bootstrap_existing_inline($xml, $idps));
        self::assertNotFalse(get_config('auth_saml2', 'metadataapproved'));
        self::assertSame($xml, get_config('auth_saml2', 'idpmetadata'));
        self::assertSame($beforehash, hash_file('sha256', $livefile));
        self::assertFalse($manager->has_pending());
    }

    public function test_upgrade_bootstrap_reads_existing_inline_config_only(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();

        self::assertTrue($manager->bootstrap_configured_inline());
        self::assertFalse($manager->bootstrap_configured_inline());

        unset_config('metadataapproved', 'auth_saml2');
        set_config('idpmetadata', 'https://idp.example.test/metadata', 'auth_saml2');
        self::assertFalse($manager->bootstrap_configured_inline());
        self::assertFalse(get_config('auth_saml2', 'metadataapproved'));
    }

    public function test_unchanged_inline_metadata_remains_approved(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $idps = (new idp_parser())->parse($xml);
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, $idps);

        self::assertSame(metadata_trust_manager::UNCHANGED, $manager->review($xml, $idps));
        self::assertFalse($manager->has_pending());
    }

    public function test_signing_key_change_is_staged_and_audited(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $approved = get_config('auth_saml2', 'metadataapproved');

        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'differentSigningCertificate=', $xml);
        $sink = $this->redirectEvents();
        $result = $manager->review($changed, (new idp_parser())->parse($changed));
        $events = $sink->get_events();
        $sink->close();

        self::assertSame(metadata_trust_manager::PENDING, $result);
        self::assertTrue($manager->has_pending());
        self::assertSame($approved, get_config('auth_saml2', 'metadataapproved'));
        self::assertTrue($manager->get_pending_summary()['signingkeys']);
        self::assertFalse($manager->get_pending_summary()['endpoints']);
        self::assertCount(1, $events);
        self::assertInstanceOf(event\metadata_change_detected::class, $events[0]);
    }

    public function test_security_endpoint_change_is_staged(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));

        $changed = str_replace(
            'https://idp.example.org/idp/profile/SAML2/Redirect/SSO',
            'https://replacement.example.org/idp/profile/SAML2/Redirect/SSO',
            $xml
        );

        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        self::assertFalse($manager->get_pending_summary()['signingkeys']);
        self::assertTrue($manager->get_pending_summary()['endpoints']);
    }
}
