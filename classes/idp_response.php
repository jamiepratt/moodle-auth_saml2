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
 * Signed responses constructed exclusively from an authorized IdP request.
 *
 * @package auth_saml2
 * @copyright 2026 Shipmate
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class idp_response {
    /**
     * Create an assertion for the current Moodle user, never a requested identity.
     *
     * @param idp_request $request Validated request and registered destination.
     * @param string $issuer This Moodle IdP's entity ID.
     * @param string $email Authenticated user's email.
     * @param array $attributes Authenticated user's profile attributes.
     * @param \SimpleSAML\XML\Signer $signer Configured local signing key.
     * @param int|null $now Clock injection for deterministic protocol fixtures.
     * @return \DOMDocument
     */
    public static function create(
        idp_request $request,
        string $issuer,
        string $email,
        array $attributes,
        \SimpleSAML\XML\Signer $signer,
        ?int $now = null,
    ): \DOMDocument {
        $now = $now ?? time();
        $instant = gmdate('Y-m-d\\TH:i:s\\Z', $now);
        $before = gmdate('Y-m-d\\TH:i:s\\Z', $now - 60);
        $after = gmdate('Y-m-d\\TH:i:s\\Z', $now + 300);
        $document = new \DOMDocument('1.0', 'UTF-8');
        $response = self::element($document, 'samlp:Response', [
            'ID' => '_' . bin2hex(random_bytes(20)),
            'InResponseTo' => $request->id,
            'Version' => '2.0',
            'IssueInstant' => $instant,
            'Destination' => $request->acs,
        ]);
        self::element($response, 'saml:Issuer', [], $issuer);
        $status = self::element($response, 'samlp:Status');
        self::element($status, 'samlp:StatusCode', ['Value' => 'urn:oasis:names:tc:SAML:2.0:status:Success']);
        $assertion = self::element($response, 'saml:Assertion', [
            'Version' => '2.0', 'IssueInstant' => $instant,
        ]);
        self::element($assertion, 'saml:Issuer', [], $issuer);
        $subject = self::element($assertion, 'saml:Subject');
        self::element($subject, 'saml:NameID', [
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        ], $email);
        $confirmation = self::element($subject, 'saml:SubjectConfirmation', [
            'Method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
        ]);
        self::element($confirmation, 'saml:SubjectConfirmationData', [
            'InResponseTo' => $request->id, 'Recipient' => $request->acs, 'NotOnOrAfter' => $after,
        ]);
        $conditions = self::element($assertion, 'saml:Conditions', ['NotBefore' => $before, 'NotOnOrAfter' => $after]);
        $audience = self::element($conditions, 'saml:AudienceRestriction');
        self::element($audience, 'saml:Audience', [], $request->sp);
        $authn = self::element($assertion, 'saml:AuthnStatement', [
            'AuthnInstant' => $instant, 'SessionIndex' => '_' . bin2hex(random_bytes(20)),
        ]);
        $context = self::element($authn, 'saml:AuthnContext');
        // A Moodle session does not prove a particular password or MFA authentication method.
        self::element($context, 'saml:AuthnContextClassRef', [], 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
        $statement = self::element($assertion, 'saml:AttributeStatement');
        foreach ($attributes as $name => $value) {
            if (!is_string($value)) {
                continue;
            }
            $attribute = self::element($statement, 'saml:Attribute', [
                'Name' => $name, 'NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified',
            ]);
            self::element($attribute, 'saml:AttributeValue', [], $value);
        }
        $signer->sign($assertion, $assertion, $subject);
        return $document;
    }

    /**
     * Keep XML escaping independent of request and profile content.
     *
     * @param \DOMNode $parent Parent document or element.
     * @param string $name Qualified protocol element name.
     * @param array $attributes Unqualified attributes.
     * @param string $text Text content.
     * @return \DOMElement
     */
    private static function element(\DOMNode $parent, string $name, array $attributes = [], string $text = ''): \DOMElement {
        $document = $parent instanceof \DOMDocument ? $parent : $parent->ownerDocument;
        $namespace = str_starts_with($name, 'samlp:') ? idp_request::PROTOCOL : idp_request::ASSERTION;
        $element = $document->createElementNS($namespace, $name);
        foreach ($attributes as $attribute => $value) {
            $element->setAttribute($attribute, $value);
        }
        if ($text !== '') {
            $element->appendChild($document->createTextNode($text));
        }
        $parent->appendChild($element);
        return $element;
    }
}
