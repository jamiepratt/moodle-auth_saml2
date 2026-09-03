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

namespace auth_saml2\testing;

/**
 * Validates the explicit cross-identity contract used by SAML Behat fixtures.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class behat_private_key_access {
    /** Behat-only environment variable containing the fixture web process GID. */
    public const ENVIRONMENT_VARIABLE = 'AUTH_SAML2_BEHAT_WEB_GID';

    /** POSIX file-type mask. */
    private const TYPE_MASK = 0170000;

    /** POSIX directory type. */
    private const TYPE_DIRECTORY = 0040000;

    /**
     * Prepare the disposable fixture directory from an explicit web GID contract.
     *
     * @param string $directory SAML fixture directory.
     * @param string|false $contract Numeric web GID supplied by the harness, or false when absent.
     * @param int $effectiveuid Effective UID of the Behat CLI process.
     * @return int|false Trusted group, or false when the fixture uses one runtime identity.
     */
    public static function prepare_directory(string $directory, string|false $contract, int $effectiveuid): int|false {
        $group = self::contract_group($contract, $effectiveuid);
        if ($group === false) {
            return false;
        }

        clearstatcache(true, $directory);
        $status = @lstat($directory);
        if ($status === false) {
            if (!mkdir($directory, 0700)) {
                throw new \RuntimeException('The SAML Behat directory could not be created securely.');
            }
        } else if (($status['mode'] & self::TYPE_MASK) !== self::TYPE_DIRECTORY) {
            throw new \RuntimeException('The SAML Behat directory must be a real directory.');
        } else if (($status['mode'] & 02000) !== 0) {
            return self::trusted_group($directory, $contract, $effectiveuid);
        }

        if (!chmod($directory, 0700) || !chgrp($directory, $group) || !chmod($directory, 02770)) {
            throw new \RuntimeException('The SAML Behat directory could not be prepared for the configured web GID.');
        }
        return self::trusted_group($directory, $contract, $effectiveuid);
    }

    /**
     * Resolve and validate the group allowed to read fixture private keys.
     *
     * @param string $directory Pre-existing SAML fixture directory.
     * @param string|false $contract Numeric web GID supplied by the harness, or false when absent.
     * @param int $effectiveuid Effective UID of the Behat CLI process.
     * @return int|false Trusted group, or false when the fixture uses one runtime identity.
     */
    public static function trusted_group(string $directory, string|false $contract, int $effectiveuid): int|false {
        $group = self::contract_group($contract, $effectiveuid);
        if ($group === false) {
            return false;
        }

        clearstatcache(true, $directory);
        $status = @lstat($directory);
        if ($status === false || ($status['mode'] & self::TYPE_MASK) !== self::TYPE_DIRECTORY) {
            throw new \RuntimeException('The SAML Behat directory must be a pre-existing real directory.');
        }
        if ($status['gid'] !== $group) {
            throw new \RuntimeException('The SAML Behat directory group does not match the configured web GID.');
        }
        if (($status['mode'] & 02000) === 0) {
            throw new \RuntimeException('The SAML Behat directory must have setgid enabled.');
        }
        if (($status['mode'] & 0002) !== 0) {
            throw new \RuntimeException('The SAML Behat directory must not be world-writable.');
        }
        if (($status['mode'] & 0030) !== 0030) {
            throw new \RuntimeException('The SAML Behat directory group must have write and execute access.');
        }
        return $group;
    }

    /**
     * Parse the explicit fixture identity contract.
     *
     * @param string|false $contract Numeric web GID supplied by the harness, or false when absent.
     * @param int $effectiveuid Effective UID of the Behat CLI process.
     * @return int|false Configured web group, or false for a same-identity non-root fixture.
     */
    private static function contract_group(string|false $contract, int $effectiveuid): int|false {
        if ($contract === false || $contract === '') {
            if ($effectiveuid === 0) {
                throw new \RuntimeException(
                    self::ENVIRONMENT_VARIABLE . ' must provide the numeric web GID when Behat CLI runs as root.'
                );
            }
            return false;
        }
        if (preg_match('/\A(?:0|[1-9][0-9]*)\z/D', $contract) !== 1 || (string) (int) $contract !== $contract) {
            throw new \RuntimeException(self::ENVIRONMENT_VARIABLE . ' must be a valid numeric GID.');
        }
        return (int) $contract;
    }
}
