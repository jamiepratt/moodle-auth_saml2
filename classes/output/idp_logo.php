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

namespace auth_saml2\output;

/**
 * Validates metadata logo URLs at the presentation boundary.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class idp_logo {
    /**
     * Accept absolute HTTP(S) image URLs, leaving stored metadata unchanged.
     *
     * @param string|null $url Metadata logo URL.
     * @return \moodle_url|null Safe image URL, or null for the default icon.
     */
    public static function url(?string $url): ?\moodle_url {
        if ($url === null || !preg_match('~^https?://~i', $url)) {
            return null;
        }
        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            return null;
        }
        return new \moodle_url($url);
    }
}
