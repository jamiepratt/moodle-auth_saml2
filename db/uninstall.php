<?php
// This file is part of SAML2 Authentication Plugin
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

/**
 * Remove plugin-owned files during uninstall.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Moodle's authentication plugin uninstall callback.
 *
 * @return bool Whether owned storage was removed successfully.
 */
function xmldb_auth_saml2_uninstall(): bool {
    global $CFG;

    $remove = function (string $path) use (&$remove): bool {
        // Check links first, including dangling links and the owned root.
        if (is_link($path) || is_file($path)) {
            return unlink($path);
        }
        if (!file_exists($path)) {
            return true;
        }
        $entries = scandir($path);
        if ($entries === false) {
            return false;
        }
        foreach ($entries as $entry) {
            if ($entry !== '.' && $entry !== '..' && !$remove($path . '/' . $entry)) {
                return false;
            }
        }
        return rmdir($path);
    };
    return $remove($CFG->dataroot . '/saml2');
}
