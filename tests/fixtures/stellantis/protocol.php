<?php
// This file is part of Moodle - https://moodle.org/
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

namespace auth_saml2\fixture;

/**
 * Synthetic, bounded SAML fixture using xmlsec1, independently of SimpleSAMLPHP.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class protocol {
    /** Synthetic IdP identity and destination. */
    public const IDP = 'idp.identity.test:saml2.0:entityId';
    /** Synthetic protocol endpoint. */
    public const SSO = 'https://idp.identity.test/idp/SSO.saml2';
    /** Synthetic portal launch endpoint. */
    public const LAUNCH = 'https://idp.identity.test/idp/startSSO.ping';
    /** Registered SP identity. */
    public const SP = 'https://sp.saml.test/auth/saml2/sp/metadata.php';
    /** Exact registered ACS. */
    public const ACS = 'https://sp.saml.test/auth/saml2/sp/saml2-acs.php/sp.saml.test';
    /** SAML protocol namespace. */
    public const P = 'urn:oasis:names:tc:SAML:2.0:protocol';
    /** SAML assertion namespace. */
    public const A = 'urn:oasis:names:tc:SAML:2.0:assertion';
    /** Supported NameID format. */
    public const NAMEID = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

    /**
     * Decode a bounded request and check the fixture registration before issuing anything.
     *
     * @param string $encoded Binding payload.
     * @param string $binding HTTP-Redirect or HTTP-POST.
     * @return array Request identity, RelayState is handled independently.
     */
    public static function request(string $encoded, string $binding): array {
        if (strlen($encoded) > 65536 || !in_array($binding, ['HTTP-Redirect', 'HTTP-POST'], true)) {
            throw new \RuntimeException('Invalid binding or size');
        }
        $xml = base64_decode($encoded, true);
        if ($binding === 'HTTP-Redirect' && $xml !== false) {
            $xml = @gzinflate($xml, 65536);
        }
        if (!$xml || str_contains($xml, '<!DOCTYPE') || str_contains($xml, '<!ENTITY')) {
            throw new \RuntimeException('Invalid request XML');
        }
        $doc = new \DOMDocument();
        if (!@$doc->loadXML($xml, LIBXML_NONET)) {
            throw new \RuntimeException('Invalid request XML');
        }
        $root = $doc->documentElement;
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('saml', self::A);
        $xpath->registerNamespace('p', self::P);
        $issuer = $xpath->query('/p:AuthnRequest/saml:Issuer');
        if (
            $root->namespaceURI !== self::P || $root->localName !== 'AuthnRequest' ||
                $root->getAttribute('Version') !== '2.0' ||
                $root->getAttribute('Destination') !== self::SSO ||
                $root->getAttribute('AssertionConsumerServiceURL') !== self::ACS ||
                $issuer->length !== 1 || $issuer[0]->textContent !== self::SP ||
                !preg_match('/^[_a-zA-Z][_a-zA-Z0-9.-]{0,200}$/D', $root->getAttribute('ID'))
        ) {
            throw new \RuntimeException('Unregistered request');
        }
        $instant = strtotime($root->getAttribute('IssueInstant'));
        if (!$instant || $instant < time() - 300 || $instant > time() + 60) {
            throw new \RuntimeException('Request time outside fixture window');
        }
        $responsebinding = $root->getAttribute('ProtocolBinding');
        if ($responsebinding !== '' && $responsebinding !== 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
            throw new \RuntimeException('Unsupported response binding');
        }
        $policies = $xpath->query('/p:AuthnRequest/p:NameIDPolicy');
        if (
            $policies->length > 1 || ($policies->length &&
                !in_array($policies[0]->getAttribute('Format'), ['', self::NAMEID], true))
        ) {
            throw new \RuntimeException('Unsupported NameIDPolicy');
        }
        return ['id' => $root->getAttribute('ID')];
    }

    /**
     * Inline metadata, with no logout service and both request bindings.
     *
     * @param string $certificate Independent synthetic public certificate.
     * @param string $binding Preferred binding, used to exercise POST separately.
     * @return string
     */
    public static function metadata(string $certificate, string $binding = 'HTTP-Redirect'): string {
        $cert = preg_replace('/-----[^-]+-----|\s/', '', $certificate);
        $services = '';
        foreach ($binding === 'HTTP-POST' ? ['HTTP-POST'] : ['HTTP-Redirect', 'HTTP-POST'] as $name) {
            $services .= '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:' . $name .
                '" Location="' . self::SSO . '"/>';
        }
        return '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' . self::IDP . '">' .
            '<md:IDPSSODescriptor protocolSupportEnumeration="' . self::P . '" WantAuthnRequestsSigned="false">' .
            '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' .
            '<ds:X509Data><ds:X509Certificate>' . $cert . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>' .
            '<md:NameIDFormat>' . self::NAMEID . '</md:NameIDFormat>' . $services .
            '<saml:Attribute xmlns:saml="' . self::A . '" Name="uid" ' .
            'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>' .
            '<saml:Attribute xmlns:saml="' . self::A . '" Name="DealerCode" ' .
            'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>' .
            '</md:IDPSSODescriptor></md:EntityDescriptor>';
    }

    /**
     * Produce a signed response. Faults are deliberate, individually selected compatibility probes.
     *
     * @param string $requestid Empty only for explicitly enabled unsolicited login.
     * @param array $attributes Synthetic attribute values, never real identities.
     * @param string $variant Probe name.
     * @param string $keydir Disposable key directory.
     * @return string Signed XML.
     */
    public static function response(string $requestid, array $attributes, string $variant, string $keydir): string {
        $doc = new \DOMDocument('1.0', 'UTF-8');
        $response = $doc->createElementNS(self::P, 'p:Response');
        $doc->appendChild($response);
        $id = '_' . bin2hex(random_bytes(16));
        $now = time();
        $before = $now - 60;
        $after = $now + 300;
        if ($variant === 'expired') {
            $before = $now - 1000;
            $after = $now - 600;
        } else if ($variant === 'future') {
            $before = $now + 600;
            $after = $now + 900;
        } else if ($variant === 'skew') {
            $before = $now + 30;
        }
        $issuer = $variant === 'issuer' ? 'https://untrusted.invalid/idp' : self::IDP;
        $destination = $variant === 'destination' ? 'https://sp.saml.test/wrong' : self::ACS;
        $correlation = $variant === 'correlation' ? '_wrong' : $requestid;
        self::attrs($response, ['ID' => $id, 'Version' => '2.0', 'IssueInstant' => gmdate('Y-m-d\TH:i:s\Z', $now),
            'Destination' => $destination]);
        if ($correlation !== '') {
            $response->setAttribute('InResponseTo', $correlation);
        }
        self::element($response, self::A, 'saml:Issuer', $issuer);
        $status = self::element($response, self::P, 'p:Status');
        self::element($status, self::P, 'p:StatusCode')->setAttribute('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
        $assertion = self::element($response, self::A, 'saml:Assertion');
        self::attrs($assertion, ['ID' => $id . '_a', 'Version' => '2.0', 'IssueInstant' => gmdate('Y-m-d\TH:i:s\Z', $now)]);
        self::element($assertion, self::A, 'saml:Issuer', $issuer);
        $subject = self::element($assertion, self::A, 'saml:Subject');
        self::element($subject, self::A, 'saml:NameID', 'synthetic-subject')->setAttribute('Format', self::NAMEID);
        $confirmation = self::element($subject, self::A, 'saml:SubjectConfirmation');
        $confirmation->setAttribute('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');
        $data = self::element($confirmation, self::A, 'saml:SubjectConfirmationData');
        self::attrs($data, ['Recipient' => $variant === 'recipient' ? 'https://sp.saml.test/wrong' : self::ACS,
            'NotOnOrAfter' => gmdate('Y-m-d\TH:i:s\Z', $after)]);
        if ($correlation !== '') {
            $data->setAttribute('InResponseTo', $correlation);
        }
        $conditions = self::element($assertion, self::A, 'saml:Conditions');
        self::attrs($conditions, ['NotBefore' => gmdate('Y-m-d\TH:i:s\Z', $before),
            'NotOnOrAfter' => gmdate('Y-m-d\TH:i:s\Z', $after)]);
        $audience = self::element($conditions, self::A, 'saml:AudienceRestriction');
        self::element($audience, self::A, 'saml:Audience', $variant === 'audience' ? 'urn:wrong' : self::SP);
        $authn = self::element($assertion, self::A, 'saml:AuthnStatement');
        self::attrs($authn, ['AuthnInstant' => gmdate('Y-m-d\TH:i:s\Z', $now), 'SessionIndex' => 'synthetic-session']);
        $context = self::element($authn, self::A, 'saml:AuthnContext');
        self::element($context, self::A, 'saml:AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
        $statement = self::element($assertion, self::A, 'saml:AttributeStatement');
        foreach ($attributes as $name => $values) {
            $attribute = self::element($statement, self::A, 'saml:Attribute');
            self::attrs($attribute, ['Name' => $name, 'NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic']);
            foreach ((array)$values as $value) {
                self::element($attribute, self::A, 'saml:AttributeValue', $value);
            }
        }
        $target = $variant === 'response-signed' ? $response : $assertion;
        self::signature($target);
        $prefix = $variant === 'untrusted' ? 'untrusted' : 'idp';
        $xml = self::sign($doc, $keydir . '/' . $prefix);
        if ($variant === 'combined') {
            $combined = new \DOMDocument();
            $combined->loadXML($xml, LIBXML_NONET);
            self::signature($combined->documentElement);
            $xml = self::sign($combined, $keydir . '/idp');
        }
        if ($variant === 'tampered') {
            $xml = str_replace('synthetic-subject', 'tampered-subject', $xml);
        }
        return $xml;
    }

    /**
     * Encrypt a signed assertion using independent OpenSSL primitives (AES128-CBC/RSA-OAEP).
     *
     * @param string $xml Signed response.
     * @param string $certificate Synthetic SP encryption certificate.
     * @return string
     */
    public static function encrypt(string $xml, string $certificate): string {
        $doc = new \DOMDocument();
        $doc->loadXML($xml, LIBXML_NONET);
        $assertion = $doc->getElementsByTagNameNS(self::A, 'Assertion')[0];
        $plaintext = $doc->saveXML($assertion);
        $key = random_bytes(16);
        $iv = random_bytes(16);
        // XML Encryption CBC padding: arbitrary padding bytes, final byte is the padding length.
        $padding = 16 - strlen($plaintext) % 16;
        $plaintext .= str_repeat("\0", $padding - 1) . chr($padding);
        $encrypted = openssl_encrypt($plaintext, 'aes-128-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($encrypted === false || !openssl_public_encrypt($key, $wrapped, $certificate, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new \RuntimeException('Synthetic assertion encryption failed');
        }
        $enc = 'http://www.w3.org/2001/04/xmlenc#';
        $ds = 'http://www.w3.org/2000/09/xmldsig#';
        $wrapper = self::element($doc->documentElement, self::A, 'saml:EncryptedAssertion');
        $data = self::element($wrapper, $enc, 'xenc:EncryptedData');
        $data->setAttribute('Type', $enc . 'Element');
        self::element($data, $enc, 'xenc:EncryptionMethod')->setAttribute('Algorithm', $enc . 'aes128-cbc');
        $info = self::element($data, $ds, 'ds:KeyInfo');
        $encryptedkey = self::element($info, $enc, 'xenc:EncryptedKey');
        self::element($encryptedkey, $enc, 'xenc:EncryptionMethod')->setAttribute('Algorithm', $enc . 'rsa-oaep-mgf1p');
        self::element(self::element($encryptedkey, $enc, 'xenc:CipherData'), $enc, 'xenc:CipherValue', base64_encode($wrapped));
        self::element(self::element($data, $enc, 'xenc:CipherData'), $enc, 'xenc:CipherValue', base64_encode($iv . $encrypted));
        $doc->documentElement->replaceChild($wrapper, $assertion);
        return $doc->saveXML();
    }

    /**
     * Append an XML element with escaped text.
     *
     * @param \DOMElement $parent Parent.
     * @param string $namespace Namespace.
     * @param string $name Qualified name.
     * @param string $text Text.
     * @return \DOMElement
     */
    private static function element(\DOMElement $parent, string $namespace, string $name, string $text = ''): \DOMElement {
        $element = $parent->ownerDocument->createElementNS($namespace, $name);
        if ($text !== '') {
            $element->appendChild($parent->ownerDocument->createTextNode($text));
        }
        $parent->appendChild($element);
        return $element;
    }

    /**
     * Set escaped attributes.
     *
     * @param \DOMElement $element Target.
     * @param array $values Values.
     */
    private static function attrs(\DOMElement $element, array $values): void {
        foreach ($values as $name => $value) {
            $element->setAttribute($name, $value);
        }
    }

    /**
     * XMLDSig template consumed by independent libxmlsec.
     *
     * @param \DOMElement $target Response or assertion.
     */
    private static function signature(\DOMElement $target): void {
        $ns = 'http://www.w3.org/2000/09/xmldsig#';
        $signature = self::element($target, $ns, 'ds:Signature');
        $target->insertBefore($signature, $target->firstChild->nextSibling);
        $info = self::element($signature, $ns, 'ds:SignedInfo');
        self::element($info, $ns, 'ds:CanonicalizationMethod')->setAttribute(
            'Algorithm',
            'http://www.w3.org/2001/10/xml-exc-c14n#'
        );
        self::element($info, $ns, 'ds:SignatureMethod')->setAttribute(
            'Algorithm',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        );
        $reference = self::element($info, $ns, 'ds:Reference');
        $reference->setAttribute('URI', '#' . $target->getAttribute('ID'));
        $transforms = self::element($reference, $ns, 'ds:Transforms');
        foreach ([$ns . 'enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'] as $algorithm) {
            self::element($transforms, $ns, 'ds:Transform')->setAttribute('Algorithm', $algorithm);
        }
        self::element($reference, $ns, 'ds:DigestMethod')->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        self::element($reference, $ns, 'ds:DigestValue');
        self::element($signature, $ns, 'ds:SignatureValue');
        $keyinfo = self::element($signature, $ns, 'ds:KeyInfo');
        self::element(self::element($keyinfo, $ns, 'ds:X509Data'), $ns, 'ds:X509Certificate');
    }

    /**
     * Sign using a separate implementation, with private temporary files and fixed arguments.
     *
     * @param \DOMDocument $document Input.
     * @param string $prefix Key/certificate prefix.
     * @return string
     */
    private static function sign(\DOMDocument $document, string $prefix): string {
        $input = tempnam(sys_get_temp_dir(), 'saml12-');
        $output = tempnam(sys_get_temp_dir(), 'saml12-');
        try {
            file_put_contents($input, $document->saveXML());
            $command = ['xmlsec1', '--sign', '--privkey-pem', $prefix . '.key,' . $prefix . '.crt',
                '--id-attr:ID', 'Assertion', '--id-attr:ID', 'Response', '--output', $output, $input];
            $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            stream_get_contents($pipes[1]);
            $error = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            if (proc_close($process) !== 0) {
                throw new \RuntimeException('Fixture signing failed: ' . $error);
            }
            return file_get_contents($output);
        } finally {
            unlink($input);
            unlink($output);
        }
    }
}
