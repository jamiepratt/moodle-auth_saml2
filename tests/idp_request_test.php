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
 * Exercise the optional IdP request trust boundary.
 *
 * @package auth_saml2
 * @copyright 2026 Shipmate
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(idp_request::class)]
final class idp_request_test extends \basic_testcase {
    /**
     * Disabled IdP configuration must never authorize an assertion.
     */
    public function test_disabled_idp_rejects_a_configured_service_provider(): void {
        $config = (object) [
            'moodleidpenabled' => 0,
            'moodleidpsplist' => 'https://sp.example/entity https://sp.example/acs',
        ];
        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage(get_string('moodleidpenabled_error', 'auth_saml2'));
        idp_request::from_redirect('', $config, 'https://moodle.example/auth/saml2/idp/sso.php');
    }
    /**
     * Arbitrary destinations cannot acquire a user's signed attributes.
     */
    public function test_request_cannot_override_the_registered_acs(): void {
        $config = (object) [
            'moodleidpenabled' => 1,
            'moodleidpsplist' => 'https://sp.example/entity https://sp.example/acs',
        ];
        $this->expectException(\moodle_exception::class);
        idp_request::from_redirect($this->request('https://attacker.example/acs'), $config, $this->endpoint());
    }

    /**
     * Legacy issuer-only rows must explain how administrators restore trust.
     */
    public function test_legacy_registration_fails_closed_with_migration_guidance(): void {
        $config = (object) ['moodleidpenabled' => 1, 'moodleidpsplist' => 'https://sp.example/entity'];
        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage('register an explicit ACS URL');
        idp_request::from_redirect($this->request(), $config, $this->endpoint());
    }

    /**
     * Malformed and unsupported protocol inputs never authorize an assertion.
     *
     * @param string $search XML to replace.
     * @param string $replacement Invalid XML/protocol input.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('invalid_requests')]
    public function test_invalid_protocol_input_is_rejected(string $search, string $replacement): void {
        $xml = str_replace($search, $replacement, gzinflate(base64_decode($this->request())));
        $config = (object) [
            'moodleidpenabled' => 1,
            'moodleidpsplist' => 'https://sp.example/entity https://sp.example/acs',
        ];
        $this->expectException(\moodle_exception::class);
        idp_request::from_redirect(base64_encode(gzdeflate($xml)), $config, $this->endpoint());
    }

    /**
     * Protocol violations include unverified subject/identity claims.
     *
     * @return array
     */
    public static function invalid_requests(): array {
        return [
            'missing ID' => [' ID="_request1"', ''],
            'numeric ID' => ['_request1', '123'],
            'ID markup' => ['_request1', '_bad&amp;quot;'],
            'ID colon' => ['_request1', 'a:b'],
            'ID whitespace' => ['_request1', ' invalid '],
            'overlong ID' => ['_request1', '_' . str_repeat('x', 256)],
            'version' => ['Version="2.0"', 'Version="1.1"'],
            'root' => ['samlp:AuthnRequest', 'samlp:LogoutRequest'],
            'protocol namespace' => ['urn:oasis:names:tc:SAML:2.0:protocol', 'urn:fake'],
            'issuer namespace' => ['urn:oasis:names:tc:SAML:2.0:assertion', 'urn:fake'],
            'duplicate issuer' => ['</saml:Issuer>', '</saml:Issuer><saml:Issuer>https://sp.example/entity</saml:Issuer>'],
            'issuer qualifier' => ['<saml:Issuer>', '<saml:Issuer NameQualifier="attacker">'],
            'issuer markup' => ['<saml:Issuer>', '<saml:Issuer><saml:NameID/>'],
            'unknown issuer' => ['https://sp.example/entity', 'https://unknown.example/entity'],
            'destination' => ['https://moodle.example/auth/saml2/idp/sso.php', 'https://elsewhere.example/sso'],
            'binding' => ['bindings:HTTP-POST', 'bindings:HTTP-Redirect'],
            'index' => ['Version="2.0"', 'Version="2.0" AssertionConsumerServiceIndex="0"'],
            'subject claim' => [
                '</samlp:AuthnRequest>',
                '<saml:Subject><saml:NameID>victim</saml:NameID></saml:Subject></samlp:AuthnRequest>',
            ],
            'force authn' => ['Version="2.0"', 'Version="2.0" ForceAuthn="true"'],
            'passive' => ['Version="2.0"', 'Version="2.0" IsPassive="true"'],
            'unsupported name ID' => [
                '</samlp:AuthnRequest>', '<samlp:NameIDPolicy Format="urn:unsupported"/></samlp:AuthnRequest>',
            ],
            'request validity claim' => [
                '</samlp:AuthnRequest>', '<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"/></samlp:AuthnRequest>',
            ],
            'doctype' => ['<samlp:AuthnRequest', '<!DOCTYPE samlp:AuthnRequest [<!ENTITY local "private">]><samlp:AuthnRequest'],
            'oversize XML' => ['</samlp:AuthnRequest>', str_repeat(' ', 65536) . '</samlp:AuthnRequest>'],
            'malformed XML' => ['</samlp:AuthnRequest>', ''],
        ];
    }

    /**
     * Requests outside the fixed freshness window must fail.
     *
     * @param string $instant Malformed or out-of-window issue instant.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('invalid_instants')]
    public function test_request_freshness_is_bounded(string $instant): void {
        $xml = preg_replace(
            '/IssueInstant="[^"]*"/',
            'IssueInstant="' . $instant . '"',
            gzinflate(base64_decode($this->request()))
        );
        $config = (object) [
            'moodleidpenabled' => 1,
            'moodleidpsplist' => 'https://sp.example/entity https://sp.example/acs',
        ];
        $this->expectException(\moodle_exception::class);
        idp_request::from_redirect(base64_encode(gzdeflate($xml)), $config, $this->endpoint(), 1800000000);
    }

    /**
     * Malformed instants and times outside five minutes old / one minute ahead.
     *
     * @return array
     */
    public static function invalid_instants(): array {
        return [
            'missing' => [''],
            'garbage' => ['next Tuesday'],
            'invalid day' => ['2027-02-31T08:00:00Z'],
            'old' => [gmdate('Y-m-d\\TH:i:s\\Z', 1800000000 - 301)],
            'future' => [gmdate('Y-m-d\\TH:i:s\\Z', 1800000000 + 61)],
        ];
    }

    /**
     * Resolve explicit and omitted ACS destinations only from registration.
     *
     * @param bool $omitacs Whether the request omits its ACS.
     * @param int $age Offset from the deterministic clock.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('allowed_requests')]
    public function test_approved_request_resolves_trusted_binding(bool $omitacs, int $age): void {
        $xml = gzinflate(base64_decode($this->request()));
        if ($omitacs) {
            $xml = str_replace(' AssertionConsumerServiceURL="https://sp.example/acs"', '', $xml);
        }
        $instant = gmdate('Y-m-d\\TH:i:s\\Z', 1800000000 + $age);
        $xml = preg_replace('/IssueInstant="[^"]*"/', 'IssueInstant="' . $instant . '"', $xml);
        $config = (object) [
            'moodleidpenabled' => 1,
            'moodleidpsplist' => 'https://sp.example/entity https://sp.example/acs',
        ];
        $request = idp_request::from_redirect(base64_encode(gzdeflate($xml)), $config, $this->endpoint(), 1800000000);
        $this->assertSame('https://sp.example/acs', $request->acs);
        $this->assertSame('https://sp.example/entity', $request->sp);
        $this->assertSame('_request1', $request->id);
    }

    /**
     * Exact freshness boundaries and default ACS selection.
     *
     * @return array
     */
    public static function allowed_requests(): array {
        return [[false, 0], [true, 0], [false, -300], [false, 60]];
    }

    /**
     * Create a synthetic HTTP-Redirect AuthnRequest.
     *
     * @param string $acs Requested destination.
     * @return string
     */
    private function request(string $acs = 'https://sp.example/acs'): string {
        $instant = gmdate('Y-m-d\\TH:i:s\\Z');
        $endpoint = $this->endpoint();
        return base64_encode(gzdeflate(<<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request1" Version="2.0"
    IssueInstant="{$instant}" Destination="{$endpoint}" AssertionConsumerServiceURL="{$acs}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>https://sp.example/entity</saml:Issuer>
</samlp:AuthnRequest>
XML));
    }

    /**
     * Synthetic IdP endpoint.
     *
     * @return string
     */
    private function endpoint(): string {
        return 'https://moodle.example/auth/saml2/idp/sso.php';
    }
}
