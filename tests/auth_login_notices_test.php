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
 * Login request and profile warning behavior.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(auth::class)]
final class auth_login_notices_test extends \advanced_testcase {
    /**
     * Test local language overrides through the profile update API.
     */
    public function test_profile_warning_uses_local_language_override(): void {
        global $CFG;

        $this->resetAfterTest();
        $oldroot = $CFG->langlocalroot;
        $CFG->langlocalroot = make_request_directory();
        mkdir($CFG->langlocalroot . '/en_local');
        file_put_contents(
            $CFG->langlocalroot . '/en_local/auth_saml2.php',
            '<?php $string["fieldnotupdated"] = ' . var_export('Protected field: {$a}', true) . ';'
        );
        get_string_manager(true)->reset_caches();
        try {
            set_config('field_map_username', 'uid', 'auth_saml2');
            set_config('field_updatelocal_username', 'onlogin', 'auth_saml2');
            $auth = get_auth_plugin('saml2');
            $user = (object)['username' => 'existing'];

            $this->assertFalse($auth->update_user_record_from_attribute_map($user, ['uid' => ['replacement']]));
            $this->assertSame('existing', $user->username);
            $notifications = \core\notification::fetch();
            $this->assertCount(1, $notifications);
            $this->assertSame('Protected field: username', $notifications[0]->get_message());
        } finally {
            $CFG->langlocalroot = $oldroot;
            get_string_manager(true)->reset_caches();
        }
    }

    /**
     * Protected field labels are escaped without exposing mapped values.
     */
    public function test_profile_warning_escapes_field_name(): void {
        $this->resetAfterTest();
        $field = 'profile_field_<b>synthetic</b>';
        set_config('mdlattr', $field, 'auth_saml2');
        set_config('field_map_' . $field, 'uid', 'auth_saml2');
        set_config('field_updatelocal_' . $field, 'onlogin', 'auth_saml2');
        $auth = get_auth_plugin('saml2');
        $user = (object)['username' => 'existing', $field => 'retained'];

        $this->assertFalse($auth->update_user_record_from_attribute_map($user, ['uid' => ['private-value']]));
        $this->assertSame('retained', $user->$field);
        $notifications = \core\notification::fetch();
        $this->assertCount(1, $notifications);
        $this->assertSame("Your profile_field_&lt;b&gt;synthetic&lt;/b&gt; wasn't updated", $notifications[0]->get_message());
        $this->assertStringNotContainsString('private-value', $notifications[0]->get_message());
    }

    /**
     * An exception marker from GET prevents a return to the IdP.
     *
     * @param mixed $get Query value, null for omitted.
     * @param mixed $post Body value, null for omitted.
     * @param bool $redirect Expected redirect decision.
     * @param string $method HTTP method.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('exception_query_provider')]
    public function test_exception_query_preserves_redirect_decision($get, $post, bool $redirect, string $method = 'GET'): void {
        $this->resetAfterTest();
        $_GET = ['saml' => 'on'];
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = $method;
        if ($get !== null) {
            $_GET['SimpleSAML_Auth_State_exceptionId'] = $get;
        }
        if ($post !== null) {
            $_POST['SimpleSAML_Auth_State_exceptionId'] = $post;
        }
        $auth = get_auth_plugin('saml2');
        $this->assertSame($redirect, $auth->should_login_redirect());
        $this->assertSame($redirect, $auth->should_login_redirect(), 'Repeated login hook keeps the same loop guard.');
        $this->assertEmpty(\core\notification::fetch());
    }

    /**
     * Provide exception query and body combinations.
     *
     * @return array
     */
    public static function exception_query_provider(): array {
        return [
            'omitted' => [null, null, true],
            'empty' => ['', null, true],
            'zero' => ['0', null, true],
            'opaque state' => ['_synthetic:state-123', null, false],
            'punctuation only' => ['...', null, false],
            'markup' => ['<b>state</b>', null, false],
            'invalid utf8' => ["\xff", null, false],
            'array' => [['state'], null, false],
            'nested array' => [[[]], null, false],
            'empty array' => [[], null, true],
            'post only ignored' => [null, '_posted-state', true],
            'get wins empty post' => ['_query-state', '', false],
            'empty get wins post' => ['', '_posted-state', true],
            'post method' => [null, null, false, 'POST'],
        ];
    }

    /**
     * Cookie selection remains GET-only even when the IdP configuration is unavailable.
     *
     * @param mixed $get Query value, null for omitted.
     * @param mixed $post Body value, null for omitted.
     * @param bool $remember Whether to remember the selected IdP.
     * @param string $method HTTP method.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('remember_query_provider')]
    public function test_remember_query_preserves_cookie_choice($get, $post, bool $remember, string $method = 'GET'): void {
        global $CFG;

        $this->resetAfterTest();
        $this->getDataGenerator()->get_plugin_generator('auth_saml2')->create_idp_entity();
        $_GET = [];
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['HTTP_HOST'] = parse_url($CFG->wwwroot, PHP_URL_HOST);
        $_SERVER['SERVER_PORT'] = 80;
        $_SERVER['REQUEST_URI'] = '/auth/saml2/login.php';
        if ($get !== null) {
            $_GET['rememberidp'] = $get;
        }
        if ($post !== null) {
            $_POST['rememberidp'] = $post;
        }
        // Capture the browser cookie boundary; the login selection itself remains real.
        $auth = new class extends auth {
            /** @var string|null Remembered IdP cookie value. */
            public ?string $remembered = null;

            /**
             * Capture the IdP cookie.
             *
             * @param string $idp IdP cookie value.
             */
            public function set_idp_cookie($idp) {
                $this->remembered = $idp;
            }
        };
        $auth->spname = 'synthetic-unconfigured-source';
        require_once($CFG->dirroot . '/auth/saml2/setup.php');
        \SimpleSAML\Session::clearInternalState();
        \SimpleSAML\Session::useTransientSession();
        try {
            $auth->saml_login();
            $this->fail('The synthetic unconfigured source must stop before contacting an IdP.');
        } catch (\SimpleSAML\Error\AuthSource $exception) {
            $expected = $remember ? reset($auth->metadataentities)->md5entityid : null;
            $this->assertSame($expected, $auth->remembered);
        } finally {
            \SimpleSAML\Session::clearInternalState();
        }
    }

    /**
     * Provide remember-choice query and body combinations.
     *
     * @return array
     */
    public static function remember_query_provider(): array {
        return [
            'omitted' => [null, null, false],
            'selected' => ['1', null, true],
            'zero' => ['0', null, false],
            'empty' => ['', null, false],
            'decimal one' => ['1.0', null, true],
            'scientific one' => ['1e0', null, true],
            'whitespace one' => [" \t1\n", null, true],
            'fraction' => ['1.5', null, false],
            'two' => ['2', null, false],
            'negative' => ['-1', null, false],
            'on' => ['on', null, false],
            'text' => ['invalid', null, false],
            'numeric prefix' => ['1invalid', null, false],
            'null byte suffix' => ["1\0", null, false],
            'form feed whitespace' => ["\f1\f", null, true],
            'array' => [['1'], null, false],
            'nested array' => [[['1']], null, false],
            'empty array' => [[], null, false],
            'post only ignored' => [null, '1', false],
            'get wins post' => ['1', '0', true],
            'get zero wins post' => ['0', '1', false],
            'get malformed wins post' => [['1'], '1', false],
            'post method query wins' => ['1', '0', true, 'POST'],
            'post method body ignored' => [null, '1', false, 'POST'],
            'post method zero wins' => ['0', '1', false, 'POST'],
        ];
    }
}
