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

use auth_saml2\testing\behat_private_key_access;

/**
 * Tests the explicit cross-identity contract used by SAML Behat fixtures.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(behat_private_key_access::class)]
final class behat_private_key_access_test extends \advanced_testcase {
    public function test_numeric_harness_group_prepares_a_disposable_fixture_directory(): void {
        $parent = make_request_directory();
        $directory = $parent . '/prepared-saml';
        $group = filegroup($parent);
        self::assertIsInt($group);

        self::assertSame(
            $group,
            behat_private_key_access::prepare_directory($directory, (string) $group, 1234)
        );
        clearstatcache(true, $directory);
        self::assertSame($group, filegroup($directory));
        self::assertSame(02770, fileperms($directory) & 07777);
    }

    public function test_numeric_harness_group_supports_a_remapped_web_identity(): void {
        $directory = make_request_directory() . '/trusted-saml';
        self::assertTrue(mkdir($directory, 02770));
        self::assertTrue(chmod($directory, 02770));
        $group = filegroup($directory);
        self::assertIsInt($group);

        self::assertSame(
            $group,
            behat_private_key_access::trusted_group($directory, (string) $group, 1234)
        );
    }

    public function test_nonroot_same_identity_fixture_needs_no_group_contract(): void {
        self::assertFalse(behat_private_key_access::trusted_group(make_request_directory(), false, 1234));
    }

    public function test_root_fixture_without_a_web_gid_contract_fails_clearly(): void {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(
            behat_private_key_access::ENVIRONMENT_VARIABLE .
            ' must provide the numeric web GID when Behat CLI runs as root.'
        );

        behat_private_key_access::trusted_group(make_request_directory(), false, 0);
    }

    public function test_web_gid_contract_must_be_numeric(): void {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(behat_private_key_access::ENVIRONMENT_VARIABLE . ' must be a valid numeric GID.');

        behat_private_key_access::trusted_group(make_request_directory(), 'www-data', 0);
    }

    public function test_web_gid_contract_must_match_the_directory_group(): void {
        $directory = $this->make_directory(02770);
        $group = filegroup($directory);
        self::assertIsInt($group);
        $othergroup = $group === PHP_INT_MAX ? $group - 1 : $group + 1;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The SAML Behat directory group does not match the configured web GID.');

        behat_private_key_access::trusted_group($directory, (string) $othergroup, 0);
    }

    public function test_web_gid_contract_requires_a_setgid_directory(): void {
        $directory = $this->make_directory(0770);
        $group = filegroup($directory);
        self::assertIsInt($group);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The SAML Behat directory must have setgid enabled.');

        behat_private_key_access::trusted_group($directory, (string) $group, 0);
    }

    public function test_web_gid_contract_rejects_a_world_writable_setgid_directory(): void {
        $directory = $this->make_directory(02777);
        $group = filegroup($directory);
        self::assertIsInt($group);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The SAML Behat directory must not be world-writable.');

        behat_private_key_access::prepare_directory($directory, (string) $group, 0);
    }

    /**
     * Make a fixture directory with an exact mode.
     *
     * @param int $mode Directory mode.
     * @return string Directory path.
     */
    private function make_directory(int $mode): string {
        $directory = make_request_directory() . '/saml-' . decoct($mode);
        self::assertTrue(mkdir($directory, $mode));
        self::assertTrue(chmod($directory, $mode));
        return $directory;
    }
}
