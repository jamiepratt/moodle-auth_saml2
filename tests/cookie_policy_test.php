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

/**
 * SAML cookie configuration must support delayed cross-site HTTPS form POSTs.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversNothing]
final class cookie_policy_test extends \advanced_testcase {
    /**
     * Secure SAML session and possession-token cookies share the cross-site policy.
     *
     * @param bool $secure Whether Moodle requires secure cookies.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('cookie_settings')]
    public function test_cookie_policy_preserves_secure_requirement(bool $secure): void {
        global $CFG, $saml2auth, $saml2config;
        $this->resetAfterTest();
        $previousauth = $saml2auth ?? null;
        $previousconfig = $saml2config ?? null;
        try {
            $CFG->cookiesecure = $secure;
            $saml2auth = new auth();
            // phpcs:ignore moodle.Files.RequireLogin.Missing -- PHPUnit loads configuration, not a web entrypoint.
            require(__DIR__ . '/../config/config.php');
            self::assertSame($secure, $config['session.cookie.secure']);
            self::assertSame($secure ? 'None' : null, $config['session.cookie.samesite']);
            self::assertSame('MDL_SSP_SessID', $config['session.cookie.name']);
            self::assertSame('MDL_SSP_AuthToken', $config['session.authtoken.cookiename']);
            self::assertSame(0, $config['session.cookie.lifetime']);
        } finally {
            $saml2auth = $previousauth;
            $saml2config = $previousconfig;
        }
    }

    /**
     * HTTPS production policy and the existing explicitly insecure HTTP test fixture.
     *
     * @return array
     */
    public static function cookie_settings(): array {
        return [[true], [false]];
    }
}
