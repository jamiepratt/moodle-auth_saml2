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

namespace auth_saml2;

/**
 * Validated request to the optional Moodle identity provider.
 *
 * @package auth_saml2
 * @copyright 2026 Shipmate
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class idp_request {
    /** @var string SAML protocol namespace. */
    public const PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var string SAML assertion namespace. */
    public const ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * Only the validator can construct an authorized request.
     *
     * @param string $id Request identifier.
     * @param string $sp Registered audience.
     * @param string $acs Registered response destination.
     */
    private function __construct(
        /** @var string Validated request identifier. */
        public readonly string $id,
        /** @var string Registered audience. */
        public readonly string $sp,
        /** @var string Registered response destination. */
        public readonly string $acs,
    ) {
    }

    /**
     * Accept an HTTP-Redirect authentication request only within configured trust.
     *
     * @param string $encoded Base64-encoded raw DEFLATE XML.
     * @param \stdClass $config Optional IdP settings.
     * @param string $endpoint This IdP's SSO endpoint.
     * @param int|null $now Clock injection for deterministic protocol fixtures.
     * @return self
     */
    public static function from_redirect(string $encoded, \stdClass $config, string $endpoint, ?int $now = null): self {
        if (empty($config->moodleidpenabled)) {
            throw new \moodle_exception('moodleidpenabled_error', 'auth_saml2');
        }
        // Bound both transfer and decompression before parsing any XML.
        if ($encoded === '' || strlen($encoded) > 131072) {
            throw self::invalid();
        }
        $compressed = base64_decode($encoded, true);
        $xml = $compressed === false ? false : @gzinflate($compressed, 65536);
        if ($xml === false || $xml === '' || strlen($xml) > 65536) {
            throw self::invalid();
        }
        $document = new \DOMDocument();
        $previous = libxml_use_internal_errors(true);
        try {
            $loaded = $document->loadXML($xml, LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        $root = $document->documentElement;
        if (
            !$loaded || $document->doctype || !$root ||
                $root->namespaceURI !== self::PROTOCOL || $root->localName !== 'AuthnRequest'
        ) {
            throw self::invalid();
        }
        self::check_attributes($root, [
            'ID', 'Version', 'IssueInstant', 'Destination', 'AssertionConsumerServiceURL',
            'ProtocolBinding', 'ForceAuthn', 'IsPassive', 'ProviderName',
        ]);
        $id = $root->getAttribute('ID');
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_.-]{0,255}$/D', $id) || $root->getAttribute('Version') !== '2.0') {
            throw self::invalid();
        }
        $now = $now ?? time();
        $instant = $root->getAttribute('IssueInstant');
        if (!preg_match('/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?Z$/D', $instant)) {
            throw self::invalid();
        }
        $format = str_contains($instant, '.') ? '!Y-m-d\\TH:i:s.u\\Z' : '!Y-m-d\\TH:i:s\\Z';
        $issued = \DateTimeImmutable::createFromFormat($format, $instant, new \DateTimeZone('UTC'));
        if (
            !$issued || \DateTimeImmutable::getLastErrors() !== false ||
                $issued->getTimestamp() < $now - 300 || $issued->getTimestamp() > $now + 60
        ) {
            throw self::invalid();
        }
        if ($root->hasAttribute('Destination') && $root->getAttribute('Destination') !== $endpoint) {
            throw self::invalid();
        }
        if (
            $root->hasAttribute('ProtocolBinding') &&
                $root->getAttribute('ProtocolBinding') !== 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        ) {
            throw self::invalid();
        }
        // Reauthentication and passive-session semantics are not implemented by this optional IdP.
        foreach (['ForceAuthn', 'IsPassive'] as $flag) {
            if ($root->hasAttribute($flag) && !in_array($root->getAttribute($flag), ['false', '0'], true)) {
                throw self::invalid();
            }
        }
        $sp = null;
        $nameidpolicy = false;
        foreach ($root->childNodes as $child) {
            if (!$child instanceof \DOMElement) {
                if ($child instanceof \DOMText && trim($child->textContent) !== '') {
                    throw self::invalid();
                }
                continue;
            }
            if ($child->namespaceURI === self::ASSERTION && $child->localName === 'Issuer' && $sp === null && !$nameidpolicy) {
                self::check_attributes($child, ['Format']);
                if (
                    $child->hasAttribute('Format') &&
                        $child->getAttribute('Format') !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
                ) {
                    throw self::invalid();
                }
                if ($child->getElementsByTagName('*')->length) {
                    throw self::invalid();
                }
                $sp = $child->textContent;
            } else if (
                $child->namespaceURI === self::PROTOCOL && $child->localName === 'NameIDPolicy' &&
                    $sp !== null && !$nameidpolicy
            ) {
                self::check_attributes($child, ['Format', 'AllowCreate']);
                if (
                    ($child->hasAttribute('Format') && !in_array($child->getAttribute('Format'), [
                    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                    ], true)) || ($child->hasAttribute('AllowCreate') &&
                    !in_array($child->getAttribute('AllowCreate'), ['true', 'false', '1', '0'], true)) ||
                    $child->getElementsByTagName('*')->length || trim($child->textContent) !== ''
                ) {
                    throw self::invalid();
                }
                $nameidpolicy = true;
            } else {
                // Never honor unsigned Subject, Conditions, Scoping or requested authentication claims.
                throw self::invalid();
            }
        }
        if ($sp === null) {
            throw self::invalid();
        }
        $acs = $root->getAttribute('AssertionConsumerServiceURL');
        $registered = self::registrations($config->moodleidpsplist ?? '')[$sp] ?? [];
        $registered = array_values(array_unique($registered));
        if (!$root->hasAttribute('AssertionConsumerServiceURL') && count($registered) === 1) {
            $acs = $registered[0];
        }
        if (!in_array($acs, $registered, true)) {
            throw new \moodle_exception('moodleidprequest_error', 'auth_saml2');
        }
        return new self($id, $sp, $acs);
    }

    /**
     * Reject attributes whose semantics this IdP cannot safely honor.
     *
     * @param \DOMElement $element Protocol element.
     * @param array $allowed Supported unqualified attribute names.
     */
    private static function check_attributes(\DOMElement $element, array $allowed): void {
        foreach ($element->attributes as $attribute) {
            if ($attribute->namespaceURI || !in_array($attribute->name, $allowed, true)) {
                throw self::invalid();
            }
        }
    }

    /**
     * Avoid echoing untrusted protocol details into user-facing errors.
     *
     * @return \moodle_exception
     */
    private static function invalid(): \moodle_exception {
        return new \moodle_exception('moodleidprequest_error', 'auth_saml2');
    }

    /**
     * Read explicit entity-ID/ACS pairs without upgrading legacy claims into trust.
     *
     * @param string $list Administrator-controlled registrations.
     * @return array
     */
    public static function registrations(string $list): array {
        $registered = [];
        foreach (preg_split('/\\R/', trim($list)) as $line) {
            if (trim($line) === '') {
                continue;
            }
            $parts = preg_split('/\\s+/', trim($line));
            if (count($parts) !== 2) {
                throw new \moodle_exception('moodleidpregistration_error', 'auth_saml2');
            }
            [$sp, $acs] = $parts;
            $url = parse_url($acs);
            if (
                !preg_match('/^[a-z][a-z0-9+.-]*:\\S+$/iD', $sp) ||
                !filter_var($acs, FILTER_VALIDATE_URL) || !$url ||
                !in_array($url['scheme'] ?? '', ['http', 'https'], true) ||
                isset($url['user']) || isset($url['pass']) || isset($url['fragment'])
            ) {
                throw new \moodle_exception('moodleidpregistration_error', 'auth_saml2');
            }
            $registered[$sp][] = $acs;
        }
        return $registered;
    }
}
