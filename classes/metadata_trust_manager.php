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

    /** Pending metadata filename. */
    private const PENDING_FILE = 'metadata.pending.json';

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
        return is_readable($this->pending_path());
    }

    /**
     * Compare fetched metadata with the approved security descriptor.
     *
     * @param string $configvalue Proposed configuration value.
     * @param idp_data[] $idps Proposed metadata sources.
     * @return string One of the review constants.
     */
    public function review(string $configvalue, array $idps): string {
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
        if (is_array($approved) && hash_equals($approved['fingerprint'] ?? '', $proposed['fingerprint'])) {
            return self::UNCHANGED;
        }

        $summary = $this->difference_summary(is_array($approved) ? $approved : [], $proposed);
        $currentpending = $this->read_pending();
        $payload = [
            'configvalue' => $configvalue,
            'configfingerprint' => hash('sha256', $configvalue),
            'idps' => array_map(static function (idp_data $idp): array {
                return [
                    'name' => $idp->idpname,
                    'url' => $idp->idpurl,
                    'icon' => $idp->idpicon,
                    'xml' => $idp->get_rawxml(),
                ];
            }, $idps),
            'descriptor' => $proposed,
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
        return $this->read_pending()['summary'] ?? null;
    }

    /**
     * Return and verify the staged configuration and metadata objects.
     *
     * @return array
     */
    public function get_pending_data(): array {
        $payload = $this->read_pending();
        if (
            !$payload || !isset(
                $payload['configvalue'],
                $payload['configfingerprint'],
                $payload['idps'],
                $payload['descriptor']
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

        return [
            'configvalue' => $payload['configvalue'],
            'idps' => $idps,
            'descriptor' => $actual,
        ];
    }

    /**
     * Mark the staged metadata approved after it has been activated.
     *
     * @param int $userid Approver user ID.
     * @param string $authority Owner or emergency delegate.
     */
    public function commit_pending(int $userid, string $authority): void {
        $this->record_pending_approval($userid, $authority);
        $this->clear_pending();
    }

    /**
     * Record approval while the caller's activation transaction is still open.
     *
     * @param int $userid Approver user ID.
     * @param string $authority Owner or emergency delegate.
     */
    public function record_pending_approval(int $userid, string $authority): void {
        $this->validate_authority($authority);
        $pending = $this->get_pending_data();
        $old = json_decode((string) get_config('auth_saml2', self::APPROVED_CONFIG), true);
        set_config(self::APPROVED_CONFIG, json_encode($pending['descriptor']), 'auth_saml2');
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
     * Remove the staged proposal after activation commits.
     */
    public function clear_pending(): void {
        if ($this->has_pending() && !unlink($this->pending_path())) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
    }

    /**
     * Record a first approved descriptor only after its activation succeeds.
     *
     * @param idp_data[] $idps Activated metadata.
     */
    public function approve_initial(array $idps): void {
        if (get_config('auth_saml2', self::APPROVED_CONFIG) === false) {
            set_config(self::APPROVED_CONFIG, json_encode($this->describe($idps)), 'auth_saml2');
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
                $entities[] = $entity->getAttribute('entityID');
            }
            if (empty($entities) || in_array('', $entities, true)) {
                throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2'));
            }

            $keys = [];
            $keyquery = '//md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]' .
                '//ds:X509Certificate | //md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]' .
                '//ds:KeyValue | //md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]' .
                '//ds11:DEREncodedKeyValue';
            foreach ($xpath->query($keyquery) as $key) {
                $normalized = preg_replace('/\s+/', '', $key->textContent);
                if ($key->localName === 'X509Certificate' || $key->localName === 'DEREncodedKeyValue') {
                    $decoded = base64_decode($normalized, true);
                    $normalized = $decoded === false ? $normalized : $decoded;
                }
                $keys[] = 'sha256:' . hash('sha256', $key->localName . ':' . $normalized);
            }

            $endpoints = [];
            $endpointquery = '//md:IDPSSODescriptor/*[' .
                'self::md:SingleSignOnService or self::md:SingleLogoutService or ' .
                'self::md:ArtifactResolutionService]';
            foreach ($xpath->query($endpointquery) as $endpoint) {
                $endpoints[] = [
                    'type' => $endpoint->localName,
                    'binding' => $endpoint->getAttribute('Binding'),
                    'location' => $endpoint->getAttribute('Location'),
                    'responselocation' => $endpoint->getAttribute('ResponseLocation'),
                ];
            }

            sort($entities);
            sort($keys);
            usort($endpoints, static fn(array $left, array $right): int => $left <=> $right);
            $sources[] = [
                'source' => $idp->idpurl,
                'entities' => $entities,
                'keys' => array_values(array_unique($keys)),
                'endpoints' => $endpoints,
            ];
        }
        usort($sources, static fn(array $left, array $right): int => $left <=> $right);

        $encoded = json_encode($sources, JSON_UNESCAPED_SLASHES);
        return [
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
            'signingkeys' => $this->field_values($approvedsources, 'keys') !==
                $this->field_values($proposedsources, 'keys'),
            'endpoints' => $this->field_values($approvedsources, 'endpoints') !==
                $this->field_values($proposedsources, 'endpoints'),
            'entities' => $this->field_values($approvedsources, 'entities') !==
                $this->field_values($proposedsources, 'entities'),
            'sources' => array_column($approvedsources, 'source') !== array_column($proposedsources, 'source'),
            'approvedfingerprint' => $approved['fingerprint'] ?? '',
            'proposedfingerprint' => $proposed['fingerprint'],
        ];
    }

    /**
     * Collect and sort descriptor values.
     *
     * @param array $sources Descriptor sources.
     * @param string $field Field name.
     * @return array
     */
    private function field_values(array $sources, string $field): array {
        $values = [];
        foreach ($sources as $source) {
            foreach ($source[$field] ?? [] as $value) {
                $values[] = $value;
            }
        }
        usort($values, static fn($left, $right): int => $left <=> $right);
        return $values;
    }

    /**
     * Read the pending metadata bundle.
     *
     * @return array|null
     */
    private function read_pending(): ?array {
        if (!$this->has_pending()) {
            return null;
        }
        $payload = json_decode((string) file_get_contents($this->pending_path()), true);
        return is_array($payload) ? $payload : null;
    }

    /**
     * Write the pending metadata bundle outside the web root.
     *
     * @param array $payload Pending bundle.
     */
    private function write_pending(array $payload): void {
        global $CFG;

        $path = $this->pending_path();
        make_writable_directory(dirname($path));
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($encoded === false) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
        $written = file_put_contents($path, $encoded, LOCK_EX);
        if ($written === false) {
            throw new \moodle_exception('idpmetadata_pendingwritefailed', 'auth_saml2');
        }
        chmod($path, $CFG->filepermissions);
    }

    /**
     * Path for staged metadata.
     *
     * @return string
     */
    private function pending_path(): string {
        global $CFG;
        return $CFG->dataroot . '/saml2/' . self::PENDING_FILE;
    }
}
