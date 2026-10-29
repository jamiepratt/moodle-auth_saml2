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

namespace auth_saml2;

use auth_saml2\fixture\protocol;
use PHPUnit\Framework\Attributes\DataProvider;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/fixtures/stellantis/protocol.php');

/**
 * Observed profile mappings and fixture request-registration boundaries.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversNothing]
final class stellantis_profile_test extends \advanced_testcase {
    /**
     * Reset configuration and use the observed, empty profile mappings.
     */
    protected function setUp(): void {
        global $CFG;
        parent::setUp();
        require_once($CFG->libdir . '/adminlib.php');
        $this->resetAfterTest();
        foreach (
            ['autocreate' => 1, 'anyauth' => 0, 'idpattr' => 'uid', 'mdlattr' => 'username',
            'field_map_firstname' => '', 'field_map_lastname' => '', 'field_map_email' => '',
            'tolower' => 2, 'attrsimple' => 0] as $key => $value
        ) {
            set_config($key, $value, 'auth_saml2');
        }
        set_config('auth', 'saml2');
    }

    /**
     * Prefixes and optional employee categories confer no access.
     *
     * @param string $uid Synthetic identifier.
     * @param string $employee Optional unconfirmed attribute.
     */
    #[DataProvider('identities')]
    public function test_existing_account_does_not_duplicate_or_grant(string $uid, string $employee): void {
        global $DB, $USER;
        $user = $this->getDataGenerator()->create_user(['username' => strtolower($uid), 'auth' => 'saml2']);
        $before = $DB->get_record('user', ['id' => $user->id]);
        $attributes = ['uid' => [$uid], 'DealerCode' => ['D0001']];
        if ($employee !== '') {
            $attributes['daimlerchryslerEmployeeType'] = [$employee];
        }
        for ($i = 0; $i < 2; $i++) {
            $this->setUser();
            @(new auth())->saml_login_complete($attributes);
            self::assertSame($user->id, $USER->id);
        }
        self::assertSame(1, $DB->count_records('user', ['username' => strtolower($uid)]));
        $after = $DB->get_record('user', ['id' => $user->id]);
        foreach (['firstname', 'lastname', 'email'] as $field) {
            self::assertSame($before->$field, $after->$field);
        }
        foreach (['role_assignments', 'user_enrolments', 'groups_members'] as $table) {
            self::assertFalse($DB->record_exists($table, ['userid' => $user->id]));
        }
        self::assertFalse(is_siteadmin($user));
    }

    /**
     * Fictional IDs, never prefix-based classifications.
     *
     * @return array
     */
    public static function identities(): array {
        return [['ab12345', ''], ['ZZ1234567890', ''], ['ea1234567890', 'employee'], ['da1234567890', 'dealer']];
    }

    /**
     * Case-insensitive mapping reuses a newly created account across UID case changes.
     */
    public function test_new_account_is_reused_after_case_change(): void {
        global $DB, $USER;
        @(new auth())->saml_login_complete(['uid' => ['ZZ1234567890'], 'DealerCode' => ['D0001']]);
        $userid = $USER->id;
        self::assertSame('zz1234567890', $USER->username);
        $this->setUser();
        @(new auth())->saml_login_complete(['uid' => ['zz1234567890'], 'DealerCode' => ['D0001']]);
        self::assertSame($userid, $USER->id);
        self::assertSame(1, $DB->count_records('user', ['username' => 'zz1234567890']));
        self::assertFalse(is_siteadmin($USER));
    }

    /**
     * Missing and case-mismatched attribute names cannot select an account.
     *
     * @param array $attributes Invalid attributes.
     */
    #[DataProvider('missing_identities')]
    public function test_missing_identity_is_rejected_without_writes(array $attributes): void {
        global $DB;
        $before = $DB->count_records('user');
        $auth = $this->getMockBuilder(auth::class)->onlyMethods(['error_page'])->getMock();
        $auth->method('error_page')->willThrowException(new \RuntimeException('Rejected'));
        try {
            $auth->saml_login_complete($attributes);
            self::fail('Invalid identity accepted');
        } catch (\RuntimeException $exception) {
            self::assertSame('Rejected', $exception->getMessage());
        }
        self::assertSame($before, $DB->count_records('user'));
    }

    /**
     * Missing values and wrong case.
     *
     * @return array
     */
    public static function missing_identities(): array {
        return [[[]], [['uid' => []]], [['UID' => ['zz1234567890']]]];
    }

    /**
     * The current UI default is a compatibility hypothesis, not measured provider behavior.
     */
    public function test_current_default_requests_transient(): void {
        $this->setAdminUser();
        $root = \admin_get_root(true, true);
        $page = $root->locate('authsettingsaml2');
        self::assertSame(
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            $page->settings->auth_saml2nameidpolicy->get_defaultsetting()
        );
    }

    /**
     * Both request bindings enforce exact registration and the supported NameID policy.
     *
     * @param string $binding Binding.
     * @param string $mutation Deliberate request change.
     */
    #[DataProvider('requests')]
    public function test_fixture_validates_requests(string $binding, string $mutation): void {
        $xml = '<p:AuthnRequest xmlns:p="' . protocol::P . '" xmlns:saml="' . protocol::A . '" ID="_test" Version="2.0"' .
            ' IssueInstant="' . gmdate('Y-m-d\TH:i:s\Z') . '" Destination="' . protocol::SSO . '"' .
            ' AssertionConsumerServiceURL="' . protocol::ACS . '"><saml:Issuer>' . protocol::SP . '</saml:Issuer>' .
            '<p:NameIDPolicy Format="' . protocol::NAMEID . '"/></p:AuthnRequest>';
        if ($mutation === 'acs') {
            $xml = str_replace(protocol::ACS, 'https://attacker.invalid/acs', $xml);
        } else if ($mutation === 'issuer') {
            $xml = str_replace(protocol::SP, 'urn:attacker', $xml);
        } else if ($mutation === 'destination') {
            $xml = str_replace(protocol::SSO, 'https://attacker.invalid/idp', $xml);
        } else if ($mutation === 'policy') {
            $xml = str_replace(protocol::NAMEID, 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', $xml);
        } else if ($mutation === 'doctype') {
            $xml = '<!DOCTYPE p:AuthnRequest [<!ENTITY x SYSTEM "file:///etc/passwd">]>' . $xml;
        }
        if ($mutation !== '') {
            $this->expectException(\RuntimeException::class);
        }
        $encoded = base64_encode($binding === 'HTTP-Redirect' ? gzdeflate($xml) : $xml);
        self::assertSame(['id' => '_test'], protocol::request($encoded, $binding));
    }

    /**
     * Request binding and fault combinations.
     *
     * @return array
     */
    public static function requests(): array {
        $cases = [];
        foreach (['HTTP-Redirect', 'HTTP-POST'] as $binding) {
            foreach (['', 'acs', 'issuer', 'destination', 'policy', 'doctype'] as $fault) {
                $cases[] = [$binding, $fault];
            }
        }
        return $cases;
    }
    /**
     * Empty and malformed signed usernames fail before account creation.
     *
     * @param string $uid Invalid username value.
     */
    #[DataProvider('invalid_usernames')]
    public function test_invalid_username_creates_no_account(string $uid): void {
        global $DB;
        $before = $DB->count_records('user');
        $failure = null;
        try {
            (new auth())->saml_login_complete(['uid' => [$uid], 'DealerCode' => ['D0001']]);
        } catch (\moodle_exception $exception) {
            $failure = $exception;
        }
        self::assertNotNull($failure);
        self::assertSame($before, $DB->count_records('user'));
        self::assertFalse(isloggedin());
    }

    /**
     * Invalid values remain rejected through Moodle username validation.
     *
     * @return array
     */
    public static function invalid_usernames(): array {
        return [[''], [' '], ['bad sid'], ['bad<sid>']];
    }
}
