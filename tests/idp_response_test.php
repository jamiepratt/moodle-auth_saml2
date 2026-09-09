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

defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * Protocol checks against signed synthetic IdP responses.
 *
 * @package auth_saml2
 * @copyright 2026 Shipmate
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(idp_response::class)]
final class idp_response_test extends \basic_testcase {
    /**
     * Signed assertions bind every recipient field and have short validity.
     */
    public function test_signed_response_binds_the_registered_service_and_request(): void {
        $now = 1800000000;
        $instant = gmdate('Y-m-d\\TH:i:s\\Z', $now);
        $xml = '<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request" Version="2.0"' .
            ' IssueInstant="' . $instant . '" AssertionConsumerServiceURL="https://sp.example/acs?one=1&amp;two=2">' .
            '<s:Issuer xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion">urn:sp:registered</s:Issuer></p:AuthnRequest>';
        $config = (object) [
            'moodleidpenabled' => 1,
            'moodleidpsplist' => 'urn:sp:registered https://sp.example/acs?one=1&two=2',
        ];
        $request = idp_request::from_redirect(base64_encode(gzdeflate($xml)), $config, 'https://idp.example/sso', $now);
        $signer = new \SimpleSAML\XML\Signer(['id' => 'ID']);
        $signer->loadPrivateKey(__DIR__ . '/fixtures/mockidp/mock.pem', 'WkKsfgAf9BhHN21LcpVYYnnt6Hr7WAJj127.0.0.1', true);
        $signer->loadCertificate(__DIR__ . '/fixtures/mockidp/mock.crt', true);
        $issuer = 'https://idp.example/metadata?one=1&two=2';
        $attributes = ['uid' => 'alice', 'custom"<&' => 'Private <profile> & "text"'];
        $response = idp_response::create($request, $issuer, 'alice@example.test', $attributes, $signer, $now);
        $xpath = new \DOMXPath($response);
        $xpath->registerNamespace('p', idp_request::PROTOCOL);
        $xpath->registerNamespace('s', idp_request::ASSERTION);
        $this->assertSame($request->acs, $xpath->evaluate('string(/p:Response/@Destination)'));
        $this->assertSame($request->id, $xpath->evaluate('string(/p:Response/@InResponseTo)'));
        $this->assertSame($request->acs, $xpath->evaluate('string(//s:SubjectConfirmationData/@Recipient)'));
        $this->assertSame($request->id, $xpath->evaluate('string(//s:SubjectConfirmationData/@InResponseTo)'));
        $this->assertSame($request->sp, $xpath->evaluate('string(//s:Audience)'));
        $this->assertSame($issuer, $xpath->evaluate('string(/p:Response/s:Issuer)'));
        $this->assertSame($issuer, $xpath->evaluate('string(//s:Assertion/s:Issuer)'));
        $this->assertSame('alice@example.test', $xpath->evaluate('string(//s:NameID)'));
        $this->assertSame($now - 60, strtotime($xpath->evaluate('string(//s:Conditions/@NotBefore)')));
        $this->assertSame($now + 300, strtotime($xpath->evaluate('string(//s:Conditions/@NotOnOrAfter)')));
        $this->assertSame($now + 300, strtotime($xpath->evaluate('string(//s:SubjectConfirmationData/@NotOnOrAfter)')));
        $this->assertSame('custom"<&', $xpath->evaluate('string(//s:Attribute[2]/@Name)'));
        $this->assertSame($attributes['custom"<&'], $xpath->evaluate('string(//s:Attribute[2]/s:AttributeValue)'));
        $ids = [];
        foreach ($xpath->query('//@ID | //s:AuthnStatement/@SessionIndex') as $id) {
            $this->assertMatchesRegularExpression('/^[A-Za-z_][A-Za-z0-9_.-]{0,255}$/', $id->value);
            $this->assertStringNotContainsString($request->id, $id->value);
            $ids[] = $id->value;
        }
        $this->assertCount(3, array_unique($ids));
        $validator = new \SimpleSAML\XML\Validator($response, 'ID', file_get_contents(__DIR__ . '/fixtures/mockidp/mock.crt'));
        $this->assertTrue($validator->isNodeValidated($xpath->query('//s:Assertion')->item(0)));
    }
}
