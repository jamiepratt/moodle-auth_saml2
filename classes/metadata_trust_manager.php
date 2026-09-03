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

use auth_saml2\admin\setting_idpmetadata;
use auth_saml2\admin\setting_idpmetadata_exception;
use DOMDocument;
use DOMXPath;

/**
 * Controls activation of security-relevant IdP metadata changes.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class metadata_trust_manager {
    /** @var int Current-process lock depth, preventing bootstrap self-recovery during activation. */
    private static int $lockdepth = 0;

    /** Maximum serialized staged proposal size (8 MiB). */
    public const MAX_PENDING_BYTES = 8 * 1024 * 1024;

    /** Maximum serialized activation recovery journal size (8 MiB). */
    public const MAX_JOURNAL_BYTES = 8 * 1024 * 1024;

    /** Lock lifetime for the bounded local activation critical section. */
    public const LOCK_LIFETIME = 900;

    /** Approval by the designated Moodle SAML service owner. */
    public const AUTHORITY_OWNER = 'serviceowner';

    /** Approval by the documented emergency delegate. */
    public const AUTHORITY_DELEGATE = 'emergencydelegate';

    /** Proposed metadata matches the approved security descriptor. */
    public const UNCHANGED = 'unchanged';

    /** Proposed metadata requires approval. */
    public const PENDING = 'pending';

    /** Config key containing the approved security descriptor. */
    private const APPROVED_CONFIG = 'metadataapproved';

    /** Config key containing the pending metadata authority. */
    private const PENDING_CONFIG = 'metadatapending';

    /** Config key containing durable activation recovery state. */
    private const ACTIVATION_CONFIG = 'metadataactivationjournal';

    /** Dedicated pending-state row name, excluded from plugin-wide config cache. */
    private const PENDING_STATE = 'pending';

    /** Dedicated activation-state row name, excluded from plugin-wide config cache. */
    private const ACTIVATION_STATE = 'activation';

    /**
     * Seed trust for already-installed inline XML without changing live metadata.
     *
     * @param string $configvalue Current configuration value.
     * @param idp_data[] $idps Parsed metadata.
     * @return bool True when a baseline was created.
     */
    public function bootstrap_existing_inline(string $configvalue, array $idps): bool {
        if (get_config('auth_saml2', self::APPROVED_CONFIG) !== false) {
            return false;
        }
        if (trim((string) get_config('auth_saml2', 'idpmetadata')) !== trim($configvalue)) {
            return false;
        }
        foreach ($idps as $idp) {
            if ($idp->idpurl !== 'xml' || $idp->get_rawxml() === null) {
                return false;
            }
        }

        set_config(self::APPROVED_CONFIG, json_encode($this->describe($idps)), 'auth_saml2');
        return true;
    }

    /**
     * Bootstrap an installed inline configuration without fetching or applying metadata.
     *
     * @return bool True when a baseline was created.
     */
    public function bootstrap_configured_inline(): bool {
        $configvalue = (string) get_config('auth_saml2', 'idpmetadata');
        if ($configvalue === '') {
            return false;
        }
        $parser = new idp_parser();
        if (!$parser->check_xml($configvalue)) {
            return false;
        }
        return $this->bootstrap_existing_inline($configvalue, $parser->parse($configvalue));
    }

    /**
     * Whether a change is waiting for approval.
     *
     * @return bool
     */
    public function has_pending(): bool {
        return $this->read_state(self::PENDING_STATE, self::PENDING_CONFIG) !== null;
    }

    /**
     * Recover any interrupted activation before presenting trust state.
     */
    public function recover(): void {
        $this->with_lock(static fn() => null);
    }

    /**
     * Recover only when durable state exists, avoiding lock acquisition on the normal path.
     */
    public function recover_if_needed(): void {
        if (self::$lockdepth > 0) {
            return;
        }
        if ($this->read_state(self::ACTIVATION_STATE, self::ACTIVATION_CONFIG) !== null) {
            $this->recover();
        }
    }

    /**
     * Compare fetched metadata with the approved security descriptor.
     *
     * @param string $configvalue Proposed configuration value.
     * @param idp_data[] $idps Proposed metadata sources.
     * @return string One of the review constants.
     */
    public function review(string $configvalue, array $idps): string {
        return $this->with_lock(fn(): string => $this->review_locked($configvalue, $idps));
    }

    /**
     * Review and apply unchanged or initial metadata under one trust-state lock.
     *
     * @param string $configvalue Proposed configuration value.
     * @param idp_data[] $idps Proposed metadata sources.
     * @param callable $activate Activation callback for an accepted proposal.
     * @return string One of the review constants.
     */
    public function review_and_apply(string $configvalue, array $idps, callable $activate): string {
        return $this->with_lock(function () use ($configvalue, $idps, $activate): string {
            $result = $this->review_locked($configvalue, $idps);
            if ($result === self::UNCHANGED) {
                $descriptor = $this->describe($idps);
                $idppayload = $this->serialize_idps($idps);
                $target = [
                    'configvalue' => $configvalue,
                    'descriptor' => $descriptor,
                    'proposalfingerprint' => $this->proposal_fingerprint($configvalue, $idppayload, $descriptor),
                ];
                $this->activate_locked($target, $activate, false, true);
            }
            return $result;
        });
    }

    /**
     * Compare metadata while holding the trust-state lock.
     *
     * @param string $configvalue Proposed configuration value.
     * @param idp_data[] $idps Proposed metadata sources.
     * @return string One of the review constants.
     */
    private function review_locked(string $configvalue, array $idps): string {
        $approved = json_decode((string) get_config('auth_saml2', self::APPROVED_CONFIG), true);
        $proposed = $this->describe($idps);
        if (!is_array($approved)) {
            $currentvalue = trim((string) get_config('auth_saml2', 'idpmetadata'));
            $inline = array_reduce($idps, static function (bool $carry, idp_data $idp): bool {
                return $carry && $idp->idpurl === 'xml';
            }, true);
            if ($currentvalue === '' || ($inline && $currentvalue === trim($configvalue))) {
                return self::UNCHANGED;
            }
        }
        if (is_array($approved)) {
            $approvedfingerprint = $approved['fingerprint'] ?? '';
            if (
                hash_equals($approvedfingerprint, $proposed['fingerprint']) ||
                (
                    !isset($approved['version']) &&
                    $this->has_unambiguous_entity_relationships($proposed) &&
                    hash_equals($approvedfingerprint, $this->legacy_fingerprint($proposed['sources']))
                )
            ) {
                return self::UNCHANGED;
            }
        }

        $summary = $this->difference_summary(is_array($approved) ? $approved : [], $proposed);
        $currentpending = $this->read_pending();
        $idppayload = $this->serialize_idps($idps);
        $payload = [
            'configvalue' => $configvalue,
            'configfingerprint' => hash('sha256', $configvalue),
            'idps' => $idppayload,
            'descriptor' => $proposed,
            'proposalfingerprint' => $this->proposal_fingerprint($configvalue, $idppayload, $proposed),
            'summary' => $summary,
            'detectedat' => time(),
        ];
        $this->write_pending($payload);
        if (($currentpending['descriptor']['fingerprint'] ?? '') !== $proposed['fingerprint']) {
            event\metadata_change_detected::create([
                'other' => [
                    'approvedfingerprint' => $approved['fingerprint'] ?? '',
                    'proposedfingerprint' => $proposed['fingerprint'],
                    'signingkeys' => $summary['signingkeys'],
                    'endpoints' => $summary['endpoints'],
                    'entities' => $summary['entities'],
                    'sources' => $summary['sources'],
                ],
            ])->trigger();
        }
        return self::PENDING;
    }

    /**
     * Return a non-sensitive summary of the staged change.
     *
     * @return array|null
     */
    public function get_pending_summary(): ?array {
        return $this->has_pending() ? $this->get_pending_review()['summary'] : null;
    }

    /**
     * Return the cryptographic identity of the exact staged proposal.
     *
     * @return string
     */
    public function get_pending_fingerprint(): string {
        return $this->get_pending_review()['proposalfingerprint'];
    }

    /**
     * Return the summary and exact form fingerprint from one locked proposal read.
     *
     * @return array{summary: array, proposalfingerprint: string, details: array}
     */
    public function get_pending_review(): array {
        return $this->with_lock(function (): array {
            $pending = $this->get_pending_data();
            $approved = json_decode((string) get_config('auth_saml2', self::APPROVED_CONFIG), true);
            return [
                'summary' => $this->difference_summary(is_array($approved) ? $approved : [], $pending['descriptor']),
                'proposalfingerprint' => $pending['proposalfingerprint'],
                'details' => $pending['descriptor']['sources'],
            ];
        });
    }

    /**
     * Return and verify the staged configuration and metadata objects.
     *
     * @param string|null $expectedfingerprint Expected proposal fingerprint, or null for any proposal.
     * @return array
     */
    public function get_pending_data(?string $expectedfingerprint = null): array {
        $payload = $this->read_pending();
        if (
            !$payload || !isset(
                $payload['configvalue'],
                $payload['configfingerprint'],
                $payload['idps'],
                $payload['descriptor'],
                $payload['proposalfingerprint']
            )
        ) {
            throw new \moodle_exception('idpmetadata_nopending', 'auth_saml2');
        }
        if (!hash_equals($payload['configfingerprint'], hash('sha256', $payload['configvalue']))) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }

        $idps = [];
        foreach ($payload['idps'] as $item) {
            $idp = new idp_data($item['name'] ?? null, $item['url'] ?? '', $item['icon'] ?? null);
            $idp->set_rawxml($item['xml'] ?? '');
            $idps[] = $idp;
        }
        $actual = $this->describe($idps);
        if (!hash_equals($payload['descriptor']['fingerprint'] ?? '', $actual['fingerprint'])) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        $actualproposal = $this->proposal_fingerprint($payload['configvalue'], $payload['idps'], $actual);
        if (!hash_equals($payload['proposalfingerprint'], $actualproposal)) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        if ($expectedfingerprint !== null && !hash_equals($actualproposal, $expectedfingerprint)) {
            throw new \moodle_exception('metadataapprovalproposalchanged', 'auth_saml2');
        }

        return [
            'configvalue' => $payload['configvalue'],
            'idps' => $idps,
            'descriptor' => $actual,
            'proposalfingerprint' => $actualproposal,
        ];
    }

    /**
     * Execute an operation while serialising metadata review and activation.
     *
     * @param callable $operation Operation to execute.
     * @return mixed Operation result.
     */
    public function with_lock(callable $operation): mixed {
        $factory = \core\lock\lock_config::get_lock_factory('auth_saml2');
        $lock = $factory->get_lock('metadata-trust', 10, self::LOCK_LIFETIME);
        if ($lock === false) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
        self::$lockdepth++;
        try {
            $this->recover_activation_locked();
            return $operation();
        } finally {
            self::$lockdepth--;
            if (!$lock->release()) {
                debugging('The SAML metadata trust lock could not be released.', DEBUG_DEVELOPER);
            }
        }
    }

    /**
     * Record approval for a verified staged proposal.
     *
     * @param array $pending Verified proposal.
     * @param int $userid Approver user ID.
     * @param string $authority Owner or emergency delegate.
     */
    public function record_approval(array $pending, int $userid, string $authority): void {
        $this->validate_authority($authority);
        $old = json_decode((string) get_config('auth_saml2', self::APPROVED_CONFIG), true);
        if (!set_config(self::APPROVED_CONFIG, json_encode($pending['descriptor']), 'auth_saml2')) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
        event\metadata_change_approved::create([
            'userid' => $userid,
            'other' => [
                'approvedfingerprint' => $pending['descriptor']['fingerprint'],
                'previousfingerprint' => $old['fingerprint'] ?? '',
                'authority' => $authority,
                'outofbandconfirmed' => 1,
            ],
        ])->trigger();
    }

    /**
     * Consume a verified proposal before activation and clean it up after success.
     *
     * @param string $expectedfingerprint Cryptographic identity shown during review.
     * @param callable $activate Activation callback receiving the verified proposal.
     */
    public function activate_pending(string $expectedfingerprint, callable $activate): void {
        $this->with_lock(function () use ($expectedfingerprint, $activate): void {
            $pending = $this->get_pending_data($expectedfingerprint);
            $this->activate_locked(
                $pending,
                static fn(callable $markcommitted) => $activate($pending, $markcommitted),
                true,
                true
            );
        });
    }

    /**
     * Journal every accepted activation, including initial and descriptor-unchanged writes.
     *
     * @param array $target Activation target.
     * @param callable $activate Callback receiving the transactional commit marker.
     * @param bool $requirespending Whether recovery must preserve an exact staged proposal.
     * @param bool $clearpending Whether success retires any older proposal.
     */
    private function activate_locked(
        array $target,
        callable $activate,
        bool $requirespending,
        bool $clearpending
    ): void {
        $this->prepare_activation_locked($target, $requirespending, $clearpending);
        $markcommitted = function () use ($target): void {
            $this->mark_activation_committed_locked($target['proposalfingerprint']);
        };
        try {
            $activate($markcommitted);
            $journal = $this->read_activation_journal();
            if (($journal['state'] ?? '') !== 'committed') {
                $this->recover_activation_locked();
                throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
            }
            $this->recover_activation_locked();
        } catch (\Throwable $exception) {
            $this->recover_activation_locked();
            throw $exception;
        }
    }

    /**
     * Delete durable metadata state.
     *
     * @param string $name Config key to delete.
     * @return bool
     */
    protected function delete_state(string $name): bool {
        global $DB;

        $statename = $name === self::PENDING_CONFIG ? self::PENDING_STATE : self::ACTIVATION_STATE;
        $table = new \xmldb_table('auth_saml2_truststate');
        if ($DB->get_manager()->table_exists($table)) {
            $DB->delete_records('auth_saml2_truststate', ['name' => $statename]);
        }
        if (get_config('auth_saml2', $name) !== false) {
            return unset_config($name, 'auth_saml2');
        }
        return true;
    }

    /**
     * Persist enough pre-activation state to recover after process death.
     *
     * @param array $pending Verified pending proposal.
     * @param bool $requirespending Whether recovery requires the matching pending proposal.
     * @param bool $clearpending Whether to clear the pending proposal after activation.
     */
    private function prepare_activation_locked(array $pending, bool $requirespending, bool $clearpending): void {
        $journal = [
            'state' => 'prepared',
            'proposalfingerprint' => $pending['proposalfingerprint'],
            'requirespending' => $requirespending,
            'clearpending' => $clearpending,
            'configfingerprint' => hash('sha256', $pending['configvalue']),
            'descriptorfingerprint' => $pending['descriptor']['fingerprint'],
            'files' => (new setting_idpmetadata())->snapshot_metadata_files(),
        ];
        $encoded = json_encode($journal, JSON_UNESCAPED_SLASHES);
        if ($encoded === false || !$this->write_state(self::ACTIVATION_STATE, $encoded, self::MAX_JOURNAL_BYTES)) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
    }

    /**
     * Mark a journal committed inside the activation's database transaction.
     *
     * @param string $proposalfingerprint Proposal identity.
     */
    private function mark_activation_committed_locked(string $proposalfingerprint): void {
        $journal = $this->read_activation_journal();
        if (
            ($journal['state'] ?? '') !== 'prepared' ||
            !hash_equals($journal['proposalfingerprint'] ?? '', $proposalfingerprint)
        ) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        $journal['state'] = 'committed';
        $encoded = json_encode($journal, JSON_UNESCAPED_SLASHES);
        if ($encoded === false || !$this->write_state(self::ACTIVATION_STATE, $encoded, self::MAX_JOURNAL_BYTES)) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
    }

    /**
     * Read and validate the activation journal container.
     *
     * @return array|null
     */
    private function read_activation_journal(): ?array {
        $encoded = $this->read_state(self::ACTIVATION_STATE, self::ACTIVATION_CONFIG);
        if ($encoded === null) {
            return null;
        }
        $journal = json_decode((string) $encoded, true);
        if (!is_array($journal)) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        return $journal;
    }

    /**
     * Recover a durable activation interrupted before its database commit.
     */
    private function recover_activation_locked(): void {
        $journal = $this->read_activation_journal();
        if ($journal === null) {
            return;
        }
        if (
            !in_array($journal['state'] ?? '', ['prepared', 'committed'], true) ||
            !isset($journal['proposalfingerprint'], $journal['files']) ||
            !is_array($journal['files'])
        ) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        if ($journal['state'] === 'prepared') {
            if (!empty($journal['requirespending']) || !array_key_exists('requirespending', $journal)) {
                $pending = $this->get_pending_data($journal['proposalfingerprint']);
                if (
                    !hash_equals($journal['descriptorfingerprint'] ?? '', $pending['descriptor']['fingerprint']) ||
                    !hash_equals($journal['configfingerprint'] ?? '', hash('sha256', $pending['configvalue']))
                ) {
                    throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
                }
            }
            (new setting_idpmetadata())->restore_metadata_files($journal['files']);
            if (!$this->delete_state(self::ACTIVATION_CONFIG)) {
                throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
            }
            return;
        }

        $requirespending = !array_key_exists('requirespending', $journal) || !empty($journal['requirespending']);
        if ($requirespending && $this->has_pending()) {
            $this->get_pending_data($journal['proposalfingerprint']);
        }

        global $DB;
        $configvalue = $DB->get_field('config_plugins', 'value', [
            'plugin' => 'auth_saml2',
            'name' => 'idpmetadata',
        ]);
        $approvedvalue = $DB->get_field('config_plugins', 'value', [
            'plugin' => 'auth_saml2',
            'name' => self::APPROVED_CONFIG,
        ]);
        $approved = json_decode((string) $approvedvalue, true);
        if (
            !hash_equals($journal['configfingerprint'] ?? '', hash('sha256', (string) $configvalue)) ||
            !hash_equals($journal['descriptorfingerprint'] ?? '', $approved['fingerprint'] ?? '')
        ) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        $clearpending = !array_key_exists('clearpending', $journal) || !empty($journal['clearpending']);
        if ($clearpending && $this->has_pending() && !$this->delete_state(self::PENDING_CONFIG)) {
            debugging('The consumed SAML metadata proposal could not be removed.', DEBUG_DEVELOPER);
            return;
        }
        if (!$this->delete_state(self::ACTIVATION_CONFIG)) {
            debugging('The completed SAML metadata activation journal could not be removed.', DEBUG_DEVELOPER);
        }
    }

    /**
     * Record a first descriptor or migrate an exact historical v1 descriptor after activation succeeds.
     *
     * @param idp_data[] $idps Activated metadata.
     */
    public function approve_initial(array $idps): void {
        $descriptor = $this->describe($idps);
        $approvedvalue = get_config('auth_saml2', self::APPROVED_CONFIG);
        $approved = json_decode((string) $approvedvalue, true);
        $shouldwrite = $approvedvalue === false;
        if (
            is_array($approved) &&
            !isset($approved['version']) &&
            $this->has_unambiguous_entity_relationships($descriptor) &&
            hash_equals($approved['fingerprint'] ?? '', $this->legacy_fingerprint($descriptor['sources']))
        ) {
            $shouldwrite = true;
        }
        if ($shouldwrite && !set_config(self::APPROVED_CONFIG, json_encode($descriptor), 'auth_saml2')) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
    }

    /**
     * Validate the declared approval authority before activation.
     *
     * @param string $authority Owner or emergency delegate.
     */
    public function validate_authority(string $authority): void {
        if (!in_array($authority, [self::AUTHORITY_OWNER, self::AUTHORITY_DELEGATE], true)) {
            throw new \invalid_parameter_exception('Invalid SAML metadata approval authority.');
        }
    }

    /**
     * Build a stable description of security-relevant metadata.
     *
     * @param idp_data[] $idps Metadata sources.
     * @return array
     */
    private function describe(array $idps): array {
        $sources = [];
        foreach ($idps as $idp) {
            $document = new DOMDocument();
            if (!$document->loadXML($idp->get_rawxml(), LIBXML_NONET | LIBXML_PARSEHUGE)) {
                throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2'));
            }
            $xpath = new DOMXPath($document);
            $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
            $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
            $xpath->registerNamespace('ds11', 'http://www.w3.org/2009/xmldsig11#');

            $entities = [];
            foreach ($xpath->query('//md:EntityDescriptor[md:IDPSSODescriptor]') as $entity) {
                $entityid = $entity->getAttribute('entityID');
                if ($entityid === '') {
                    throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2'));
                }

                $keys = [];
                $keyquery = './md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]' .
                    '//ds:X509Certificate | ./md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]' .
                    '//ds:KeyValue | ./md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]' .
                    '//ds11:DEREncodedKeyValue';
                foreach ($xpath->query($keyquery, $entity) as $key) {
                    $normalized = preg_replace('/\s+/', '', $key->textContent);
                    if ($key->localName === 'X509Certificate' || $key->localName === 'DEREncodedKeyValue') {
                        $decoded = base64_decode($normalized, true);
                        $normalized = $decoded === false ? $normalized : $decoded;
                    }
                    $keys[] = 'sha256:' . hash('sha256', $key->localName . ':' . $normalized);
                }

                $endpoints = [];
                $endpointquery = './md:IDPSSODescriptor/*[' .
                    'self::md:SingleSignOnService or self::md:SingleLogoutService or ' .
                    'self::md:ArtifactResolutionService]';
                foreach ($xpath->query($endpointquery, $entity) as $endpoint) {
                    $endpoints[] = [
                        'type' => $endpoint->localName,
                        'binding' => $endpoint->getAttribute('Binding'),
                        'location' => $endpoint->getAttribute('Location'),
                        'responselocation' => $endpoint->getAttribute('ResponseLocation'),
                        'index' => $endpoint->getAttribute('index'),
                        'isdefault' => $endpoint->getAttribute('isDefault'),
                    ];
                }

                sort($keys);
                usort($endpoints, static fn(array $left, array $right): int => $left <=> $right);
                $entities[] = [
                    'entityid' => $entityid,
                    'signingkeys' => array_values(array_unique($keys)),
                    'endpoints' => $endpoints,
                ];
            }
            if (empty($entities)) {
                throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2'));
            }
            usort($entities, static fn(array $left, array $right): int => $left <=> $right);
            $sources[] = [
                'source' => $idp->idpurl,
                'entities' => $entities,
            ];
        }
        usort($sources, static fn(array $left, array $right): int => $left <=> $right);

        $encoded = json_encode($sources, JSON_UNESCAPED_SLASHES);
        return [
            'version' => 2,
            'fingerprint' => hash('sha256', $encoded),
            'sources' => $sources,
        ];
    }

    /**
     * Compare approved and proposed descriptors.
     *
     * @param array $approved Approved descriptor.
     * @param array $proposed Proposed descriptor.
     * @return array
     */
    private function difference_summary(array $approved, array $proposed): array {
        $approvedsources = $approved['sources'] ?? [];
        $proposedsources = $proposed['sources'] ?? [];
        return [
            'signingkeys' => $this->relationship_values($approvedsources, 'signingkeys') !==
                $this->relationship_values($proposedsources, 'signingkeys'),
            'endpoints' => $this->relationship_values($approvedsources, 'endpoints') !==
                $this->relationship_values($proposedsources, 'endpoints'),
            'entities' => $this->entity_values($approvedsources) !== $this->entity_values($proposedsources),
            'sources' => array_column($approvedsources, 'source') !== array_column($proposedsources, 'source'),
            'approvedfingerprint' => $approved['fingerprint'] ?? '',
            'proposedfingerprint' => $proposed['fingerprint'],
        ];
    }

    /**
     * Hash the exact configuration and resolved metadata presented for approval.
     *
     * @param string $configvalue Proposed setting value.
     * @param array $idps Serialized resolved metadata sources.
     * @param array $descriptor Security descriptor.
     * @return string
     */
    private function proposal_fingerprint(string $configvalue, array $idps, array $descriptor): string {
        $encoded = json_encode([$configvalue, $idps, $descriptor], JSON_UNESCAPED_SLASHES);
        if ($encoded === false) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
        return hash('sha256', $encoded);
    }

    /**
     * Serialize resolved IdP sources into a durable bounded proposal.
     *
     * @param idp_data[] $idps Resolved sources.
     * @return array Serialized sources.
     */
    private function serialize_idps(array $idps): array {
        return array_map(static function (idp_data $idp): array {
            return [
                'name' => $idp->idpname,
                'url' => $idp->idpurl,
                'icon' => $idp->idpicon,
                'xml' => $idp->get_rawxml(),
            ];
        }, $idps);
    }

    /**
     * Collect and sort descriptor values.
     *
     * @param array $sources Descriptor sources.
     * @param string $field Field name.
     * @return array
     */
    private function relationship_values(array $sources, string $field): array {
        $values = [];
        foreach ($sources as $source) {
            foreach ($source['entities'] ?? [] as $entity) {
                if (!is_array($entity)) {
                    foreach ($source[$field === 'signingkeys' ? 'keys' : $field] ?? [] as $value) {
                        $values[] = [$source['source'] ?? '', $entity, $value];
                    }
                    continue;
                }
                foreach ($entity[$field] ?? [] as $value) {
                    $values[] = [$source['source'] ?? '', $entity['entityid'] ?? '', $value];
                }
            }
        }
        usort($values, static fn($left, $right): int => $left <=> $right);
        return $values;
    }

    /**
     * Collect source and entity identities from either descriptor format.
     *
     * @param array $sources Descriptor sources.
     * @return array
     */
    private function entity_values(array $sources): array {
        $values = [];
        foreach ($sources as $source) {
            foreach ($source['entities'] ?? [] as $entity) {
                $values[] = [$source['source'] ?? '', is_array($entity) ? ($entity['entityid'] ?? '') : $entity];
            }
        }
        usort($values, static fn($left, $right): int => $left <=> $right);
        return $values;
    }

    /**
     * Whether an old flattened descriptor represented relationships without ambiguity.
     *
     * @param array $descriptor Version 2 descriptor.
     * @return bool
     */
    private function has_unambiguous_entity_relationships(array $descriptor): bool {
        foreach ($descriptor['sources'] ?? [] as $source) {
            if (count($source['entities'] ?? []) !== 1) {
                return false;
            }
        }
        return !empty($descriptor['sources']);
    }

    /**
     * Reproduce the version 1 flattened fingerprint for safe single-entity compatibility.
     *
     * @param array $sources Version 2 sources.
     * @return string
     */
    private function legacy_fingerprint(array $sources): string {
        $legacy = [];
        foreach ($sources as $source) {
            $entityids = [];
            $keys = [];
            $endpoints = [];
            foreach ($source['entities'] ?? [] as $entity) {
                $entityids[] = $entity['entityid'];
                $keys = array_merge($keys, $entity['signingkeys']);
                foreach ($entity['endpoints'] as $endpoint) {
                    $endpoints[] = [
                        'type' => $endpoint['type'],
                        'binding' => $endpoint['binding'],
                        'location' => $endpoint['location'],
                        'responselocation' => $endpoint['responselocation'],
                    ];
                }
            }
            sort($entityids);
            sort($keys);
            usort($endpoints, static fn(array $left, array $right): int => $left <=> $right);
            $legacy[] = [
                'source' => $source['source'],
                'entities' => $entityids,
                'keys' => array_values(array_unique($keys)),
                'endpoints' => $endpoints,
            ];
        }
        usort($legacy, static fn(array $left, array $right): int => $left <=> $right);
        return hash('sha256', json_encode($legacy, JSON_UNESCAPED_SLASHES));
    }

    /**
     * Read the pending metadata bundle.
     *
     * @return array|null
     */
    private function read_pending(): ?array {
        $contents = $this->read_state(self::PENDING_STATE, self::PENDING_CONFIG);
        if ($contents === null) {
            return null;
        }
        $payload = json_decode((string) $contents, true);
        if (!is_array($payload)) {
            throw new \moodle_exception('idpmetadata_pendinginvalid', 'auth_saml2');
        }
        return $payload;
    }

    /**
     * Write the pending metadata bundle to shared Moodle database storage.
     *
     * @param array $payload Pending bundle.
     */
    private function write_pending(array $payload): void {
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($encoded === false || !$this->write_state(self::PENDING_STATE, $encoded, self::MAX_PENDING_BYTES)) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
    }

    /**
     * Read dedicated state, accepting a legacy config value until the upgrade migrates it.
     *
     * @param string $name State row name.
     * @param string $legacyconfig Legacy config key.
     * @return string|null Stored value.
     */
    private function read_state(string $name, string $legacyconfig): ?string {
        global $DB;

        try {
            $value = $DB->get_field('auth_saml2_truststate', 'value', ['name' => $name]);
        } catch (\dml_exception $exception) {
            $table = new \xmldb_table('auth_saml2_truststate');
            if ($DB->get_manager()->table_exists($table)) {
                throw $exception;
            }
            $value = false;
        }
        if ($value !== false) {
            return (string) $value;
        }
        $legacy = get_config('auth_saml2', $legacyconfig);
        return $legacy === false ? null : (string) $legacy;
    }

    /**
     * Persist bounded state outside the plugin-wide config cache.
     *
     * @param string $name State row name.
     * @param string $value Encoded state.
     * @param int $maximum Maximum encoded bytes.
     * @return bool Success.
     */
    private function write_state(string $name, string $value, int $maximum): bool {
        global $DB;

        if (strlen($value) > $maximum) {
            return false;
        }
        $record = $DB->get_record('auth_saml2_truststate', ['name' => $name]);
        if ($record) {
            $record->value = $value;
            $record->timemodified = time();
            return $DB->update_record('auth_saml2_truststate', $record);
        }
        return (bool) $DB->insert_record('auth_saml2_truststate', (object) [
            'name' => $name,
            'value' => $value,
            'timemodified' => time(),
        ]);
    }
}
