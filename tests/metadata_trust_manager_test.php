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

    public function test_pending_proposal_uses_shared_moodle_storage_not_a_runtime_identity_file(): void {
        global $CFG;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'restrictedSigningCertificate=', $xml);

        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );

        $path = $CFG->dataroot . '/saml2/metadata.pending.json';
        self::assertFileDoesNotExist($path);
        $review = (new metadata_trust_manager())->get_pending_review();
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $review['proposalfingerprint']);
    }

    public function test_pending_review_binds_the_summary_and_form_fingerprint_to_one_proposal(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'reviewBundleCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );

        $review = $manager->get_pending_review();

        self::assertTrue($review['summary']['signingkeys']);
        self::assertSame($manager->get_pending_fingerprint(), $review['proposalfingerprint']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $review['proposalfingerprint']);
    }

    public function test_cleanup_failure_after_success_does_not_report_activation_failure_or_leave_pending_state(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new class extends metadata_trust_manager {
            /**
             * Simulate a post-activation cleanup failure.
             *
             * @param string $name State key to delete.
             * @return bool
             */
            protected function delete_state(string $name): bool {
                static $failed = false;
                if ($name === 'metadatapending' && !$failed) {
                    $failed = true;
                    return false;
                }
                return parent::delete_state($name);
            }
        };
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'cleanupFailureCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        $fingerprint = $manager->get_pending_fingerprint();
        $activated = false;

        $manager->activate_pending($fingerprint, function (
            array $pending,
            callable $markcommitted
        ) use (
            $manager,
            &$activated
        ): void {
            set_config('idpmetadata', $pending['configvalue'], 'auth_saml2');
            $manager->record_approval($pending, get_admin()->id, metadata_trust_manager::AUTHORITY_OWNER);
            $markcommitted();
            $activated = true;
        });

        $this->assertDebuggingCalled('The consumed SAML metadata proposal could not be removed.');
        self::assertTrue($activated);
        self::assertTrue($manager->has_pending());
        (new metadata_trust_manager())->recover();
        self::assertFalse((new metadata_trust_manager())->has_pending());
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_activation_without_a_transactional_commit_marker_rolls_back_to_reviewable_state(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'missingCommitMarkerCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        $fingerprint = $manager->get_pending_fingerprint();

        try {
            $manager->activate_pending($fingerprint, static function (): void {
                // Simulate a process returning without committing its database-backed activation.
            });
            self::fail('Activation without the durable commit marker must fail closed.');
        } catch (\moodle_exception $exception) {
            self::assertSame(get_string('idpmetadata_pendinginvalid', 'auth_saml2'), $exception->getMessage());
        }

        self::assertTrue($manager->has_pending());
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_transaction_rollback_after_commit_marker_recovers_from_durable_prepared_state(): void {
        global $DB;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $approved = get_config('auth_saml2', 'metadataapproved');
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'rolledBackCommitCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        $fingerprint = $manager->get_pending_fingerprint();

        try {
            $manager->activate_pending($fingerprint, static function (
                array $pending,
                callable $markcommitted
            ) use ($DB): void {
                $transaction = $DB->start_delegated_transaction();
                set_config('idpmetadata', $pending['configvalue'], 'auth_saml2');
                set_config('metadataapproved', json_encode($pending['descriptor']), 'auth_saml2');
                $markcommitted();
                $transaction->rollback(new \moodle_exception('idpmetadata_writefailed', 'auth_saml2'));
            });
            self::fail('A database rollback after the marker must abort activation.');
        } catch (\moodle_exception $exception) {
            self::assertSame(get_string('idpmetadata_writefailed', 'auth_saml2'), $exception->getMessage());
        }

        self::assertSame($xml, $DB->get_field('config_plugins', 'value', [
            'plugin' => 'auth_saml2',
            'name' => 'idpmetadata',
        ]));
        self::assertSame($approved, $DB->get_field('config_plugins', 'value', [
            'plugin' => 'auth_saml2',
            'name' => 'metadataapproved',
        ]));
        self::assertTrue($manager->has_pending());
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_prepared_activation_journal_restores_live_files_and_keeps_the_proposal_reviewable(): void {
        global $CFG;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'crashRecoveryCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        $pending = $manager->get_pending_data();
        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $livefile = $directory . '/' . md5('xml') . '.idp.xml';
        file_put_contents($livefile, trim($xml));
        chmod($livefile, 0400);
        $snapshot = [$livefile => [
            'contents' => trim($xml),
            'owner' => fileowner($livefile),
            'group' => filegroup($livefile),
            'mode' => 0400,
        ]];
        set_config('metadataactivationjournal', json_encode([
            'state' => 'prepared',
            'proposalfingerprint' => $pending['proposalfingerprint'],
            'configfingerprint' => hash('sha256', $pending['configvalue']),
            'descriptorfingerprint' => $pending['descriptor']['fingerprint'],
            'files' => $snapshot,
        ], JSON_UNESCAPED_SLASHES), 'auth_saml2');
        file_put_contents($livefile, trim($changed));
        chmod($livefile, 0600);

        $review = (new metadata_trust_manager())->get_pending_review();

        self::assertSame($pending['proposalfingerprint'], $review['proposalfingerprint']);
        self::assertSame(trim($xml), file_get_contents($livefile));
        clearstatcache(true, $livefile);
        self::assertSame(0400, fileperms($livefile) & 0777);
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_prepared_activation_journal_before_live_writes_does_not_hide_the_proposal(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'preparedOnlyCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        $pending = $manager->get_pending_data();
        set_config('metadataactivationjournal', json_encode([
            'state' => 'prepared',
            'proposalfingerprint' => $pending['proposalfingerprint'],
            'configfingerprint' => hash('sha256', $pending['configvalue']),
            'descriptorfingerprint' => $pending['descriptor']['fingerprint'],
            'files' => [],
        ], JSON_UNESCAPED_SLASHES), 'auth_saml2');

        $review = (new metadata_trust_manager())->get_pending_review();

        self::assertSame($pending['proposalfingerprint'], $review['proposalfingerprint']);
        self::assertTrue((new metadata_trust_manager())->has_pending());
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_committed_activation_journal_finishes_cleanup_without_rolling_back_live_metadata(): void {
        global $CFG;

        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $changed = str_replace('q1og9SGCUU2yRL1tC+Y=', 'committedCrashCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($changed, (new idp_parser())->parse($changed))
        );
        $pending = $manager->get_pending_data();
        $directory = $CFG->dataroot . '/saml2';
        make_writable_directory($directory);
        $livefile = $directory . '/' . md5('xml') . '.idp.xml';
        file_put_contents($livefile, trim($changed));
        set_config('idpmetadata', $pending['configvalue'], 'auth_saml2');
        set_config('metadataapproved', json_encode($pending['descriptor']), 'auth_saml2');
        set_config('metadataactivationjournal', json_encode([
            'state' => 'committed',
            'proposalfingerprint' => $pending['proposalfingerprint'],
            'configfingerprint' => hash('sha256', $pending['configvalue']),
            'descriptorfingerprint' => $pending['descriptor']['fingerprint'],
            'files' => [],
        ], JSON_UNESCAPED_SLASHES), 'auth_saml2');

        (new metadata_trust_manager())->recover();

        self::assertSame(trim($changed), file_get_contents($livefile));
        self::assertFalse((new metadata_trust_manager())->has_pending());
        self::assertFalse(get_config('auth_saml2', 'metadataactivationjournal'));
    }

    public function test_committed_activation_journal_cannot_consume_a_replaced_pending_proposal(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $proposal = str_replace('q1og9SGCUU2yRL1tC+Y=', 'committedProposalCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($proposal, (new idp_parser())->parse($proposal))
        );
        $committed = $manager->get_pending_data();
        $replacement = str_replace('q1og9SGCUU2yRL1tC+Y=', 'replacementProposalCertificate=', $xml);
        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($replacement, (new idp_parser())->parse($replacement))
        );
        $replacementfingerprint = $manager->get_pending_fingerprint();
        set_config('idpmetadata', $committed['configvalue'], 'auth_saml2');
        set_config('metadataapproved', json_encode($committed['descriptor']), 'auth_saml2');
        set_config('metadataactivationjournal', json_encode([
            'state' => 'committed',
            'proposalfingerprint' => $committed['proposalfingerprint'],
            'configfingerprint' => hash('sha256', $committed['configvalue']),
            'descriptorfingerprint' => $committed['descriptor']['fingerprint'],
            'files' => [],
        ], JSON_UNESCAPED_SLASHES), 'auth_saml2');

        try {
            (new metadata_trust_manager())->recover();
            self::fail('Recovery must not consume a proposal that was not activated.');
        } catch (\moodle_exception $exception) {
            self::assertSame(get_string('metadataapprovalproposalchanged', 'auth_saml2'), $exception->getMessage());
        }

        $stillpending = json_decode((string) get_config('auth_saml2', 'metadatapending'), true);
        self::assertSame($replacementfingerprint, $stillpending['proposalfingerprint']);
        self::assertNotFalse(get_config('auth_saml2', 'metadataactivationjournal'));
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

    public function test_moving_signing_keys_between_entities_requires_approval(): void {
        $this->resetAfterTest();
        $baseline = $this->multi_entity_metadata(
            'key-a',
            'key-b',
            'https://sso-a.example/login',
            'https://sso-b.example/login'
        );
        set_config('idpmetadata', $baseline, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($baseline, (new idp_parser())->parse($baseline));
        $moved = $this->multi_entity_metadata(
            'key-b',
            'key-a',
            'https://sso-a.example/login',
            'https://sso-b.example/login'
        );

        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($moved, (new idp_parser())->parse($moved))
        );
        self::assertTrue($manager->get_pending_summary()['signingkeys']);
    }

    public function test_moving_endpoints_between_entities_requires_approval(): void {
        $this->resetAfterTest();
        $baseline = $this->multi_entity_metadata(
            'key-a',
            'key-b',
            'https://sso-a.example/login',
            'https://sso-b.example/login'
        );
        set_config('idpmetadata', $baseline, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($baseline, (new idp_parser())->parse($baseline));
        $moved = $this->multi_entity_metadata(
            'key-a',
            'key-b',
            'https://sso-b.example/login',
            'https://sso-a.example/login'
        );

        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($moved, (new idp_parser())->parse($moved))
        );
        self::assertTrue($manager->get_pending_summary()['endpoints']);
    }

    public function test_duplicate_signing_key_reuse_across_entities_requires_approval(): void {
        $this->resetAfterTest();
        $baseline = $this->multi_entity_metadata(
            'key-a',
            'key-b',
            'https://sso-a.example/login',
            'https://sso-b.example/login'
        );
        set_config('idpmetadata', $baseline, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($baseline, (new idp_parser())->parse($baseline));
        $reused = $this->multi_entity_metadata(
            'key-a',
            'key-a',
            'https://sso-a.example/login',
            'https://sso-b.example/login'
        );

        self::assertSame(
            metadata_trust_manager::PENDING,
            $manager->review($reused, (new idp_parser())->parse($reused))
        );
        self::assertTrue($manager->get_pending_summary()['signingkeys']);
    }

    public function test_entity_and_metadata_element_order_does_not_change_trust(): void {
        $this->resetAfterTest();
        $baseline = $this->multi_entity_metadata(
            'key-a',
            'key-b',
            'https://sso-a.example/login',
            'https://sso-b.example/login'
        );
        set_config('idpmetadata', $baseline, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($baseline, (new idp_parser())->parse($baseline));
        $reordered = $this->multi_entity_metadata(
            'key-a',
            'key-b',
            'https://sso-a.example/login',
            'https://sso-b.example/login',
            true
        );

        self::assertSame(
            metadata_trust_manager::UNCHANGED,
            $manager->review($reordered, (new idp_parser())->parse($reordered))
        );
    }

    public function test_legacy_single_entity_descriptor_remains_compatible(): void {
        $this->resetAfterTest();
        $xml = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        set_config('idpmetadata', $xml, 'auth_saml2');
        $manager = new metadata_trust_manager();
        $manager->bootstrap_existing_inline($xml, (new idp_parser())->parse($xml));
        $descriptor = json_decode(get_config('auth_saml2', 'metadataapproved'), true);
        $source = $descriptor['sources'][0];
        $entity = $source['entities'][0];
        $legacysources = [[
            'source' => $source['source'],
            'entities' => [$entity['entityid']],
            'keys' => $entity['signingkeys'],
            'endpoints' => $entity['endpoints'],
        ]];
        set_config('metadataapproved', json_encode([
            'fingerprint' => hash('sha256', json_encode($legacysources, JSON_UNESCAPED_SLASHES)),
            'sources' => $legacysources,
        ]), 'auth_saml2');

        self::assertSame(
            metadata_trust_manager::UNCHANGED,
            $manager->review($xml, (new idp_parser())->parse($xml))
        );
        self::assertFalse($manager->has_pending());
    }

    /**
     * Build deterministic metadata containing two independently trusted entities.
     *
     * @param string $keya Signing key material for entity A.
     * @param string $keyb Signing key material for entity B.
     * @param string $endpointa Endpoint suffix for entity A.
     * @param string $endpointb Endpoint suffix for entity B.
     * @param bool $reverseentities Whether entity B should appear first.
     * @return string
     */
    private function multi_entity_metadata(
        string $keya,
        string $keyb,
        string $endpointa,
        string $endpointb,
        bool $reverseentities = false
    ): string {
        $entitya = <<<XML
                <md:EntityDescriptor entityID="https://entity-a.example/idp">
                    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
                            <ds:X509Certificate>{$keya}</ds:X509Certificate>
                        </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="{$endpointa}" />
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>
            XML;
        $entityb = <<<XML
                <md:EntityDescriptor entityID="https://entity-b.example/idp">
                    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
                            <ds:X509Certificate>{$keyb}</ds:X509Certificate>
                        </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="{$endpointb}" />
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>
            XML;
        $entities = $reverseentities ? $entityb . $entitya : $entitya . $entityb;
        return <<<XML
            <?xml version="1.0"?>
            <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {$entities}
            </md:EntitiesDescriptor>
            XML;
    }
}
