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

/**
 * Safely removes world access from plugin-owned SP private keys.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class private_key_permissions {
    /** POSIX file-type mask. */
    private const TYPE_MASK = 0170000;

    /** POSIX regular-file type. */
    private const TYPE_REGULAR = 0100000;

    /** POSIX directory type. */
    private const TYPE_DIRECTORY = 0040000;

    /**
     * Harden every direct host-named private key in the SAML storage directory.
     *
     * @param string $directory SAML storage directory.
     */
    public function harden_directory(string $directory): void {
        $directorystat = $this->inspect_path($directory, self::TYPE_DIRECTORY, true);
        if ($directorystat === null) {
            return;
        }
        $entries = scandir($directory);
        if ($entries === false) {
            throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
        }
        foreach ($entries as $filename) {
            if (!$this->is_private_key_filename($filename)) {
                continue;
            }
            $path = $directory . DIRECTORY_SEPARATOR . $filename;
            $initial = $this->inspect_path($path, self::TYPE_REGULAR);
            $mode = $initial['mode'] & 0777;
            if (($mode & 0007) === 0) {
                continue;
            }

            $this->before_permission_change($path);
            $current = $this->inspect_path($path, self::TYPE_REGULAR);
            if (!$this->same_file($initial, $current, true)) {
                throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
            }
            $safemode = ($mode & 0600) | 0400;
            if (!chmod($path, $safemode)) {
                throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
            }
            $updated = $this->inspect_path($path, self::TYPE_REGULAR);
            if (!$this->same_file($initial, $updated) || ($updated['mode'] & 0777) !== $safemode) {
                throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
            }
        }
        $currentdirectory = $this->inspect_path($directory, self::TYPE_DIRECTORY);
        if (!$this->same_file($directorystat, $currentdirectory, true)) {
            throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
        }
    }

    /**
     * Hook for deterministic replacement-race testing.
     *
     * @param string $path Private-key path about to be changed.
     */
    protected function before_permission_change(string $path): void {
    }

    /**
     * Read path metadata without following symbolic links.
     *
     * @param string $path Path to inspect.
     * @return array|false lstat result, or false when unavailable.
     */
    protected function path_status(string $path): array|false {
        clearstatcache(true, $path);
        return @lstat($path);
    }

    /**
     * Inspect a path without following symbolic links.
     *
     * @param string $path Path to inspect.
     * @param int $expectedtype Required POSIX file type.
     * @param bool $allowmissing Whether an absent path is acceptable.
     * @return array|null lstat result, or null for an allowed absent path.
     */
    private function inspect_path(string $path, int $expectedtype, bool $allowmissing = false): ?array {
        $stat = $this->path_status($path);
        if ($stat === false) {
            if ($allowmissing && !is_link($path)) {
                return null;
            }
            throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
        }
        if (($stat['mode'] & self::TYPE_MASK) !== $expectedtype) {
            throw new \moodle_exception('privatekeypermissionupgradefailed', 'auth_saml2');
        }
        return $stat;
    }

    /**
     * Whether two no-follow inspections identify the same entry.
     *
     * @param array $expected Earlier lstat result.
     * @param array $actual Later lstat result.
     * @param bool $samemode Whether permission bits must also be unchanged.
     */
    private function same_file(array $expected, array $actual, bool $samemode = false): bool {
        return $expected['dev'] === $actual['dev'] &&
            $expected['ino'] === $actual['ino'] &&
            ($expected['mode'] & self::TYPE_MASK) === ($actual['mode'] & self::TYPE_MASK) &&
            (!$samemode || ($expected['mode'] & 07777) === ($actual['mode'] & 07777));
    }

    /**
     * Whether a direct filename can have been produced from an SP host name.
     *
     * @param string $filename Direct directory entry name.
     */
    private function is_private_key_filename(string $filename): bool {
        return preg_match(
            '/\A(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[A-Fa-f0-9:]+|\[[A-Fa-f0-9:.]+\])\.pem\z/D',
            $filename
        ) === 1;
    }
}
