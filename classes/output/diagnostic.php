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
 * Safe output helpers for the SAML diagnostic page.
 *
 * @package    auth_saml2
 * @copyright  2026 Shipmate
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class diagnostic {
    /**
     * Render a labelled value as encoded paragraph text.
     *
     * @param string $label Trusted label.
     * @param string $value External value.
     * @return string
     */
    public static function paragraph(string $label, string $value): string {
        return \html_writer::tag('p', s($label) . s($value));
    }

    /**
     * Render a labelled value as encoded heading text.
     *
     * @param string $label Trusted label.
     * @param string $value External value.
     * @return string
     */
    public static function heading(string $label, string $value): string {
        return \html_writer::tag('h4', s($label) . s($value));
    }

    /**
     * Render attribute JSON as encoded text within a structural pre element.
     *
     * @param mixed $value Value to encode.
     * @return string
     */
    public static function json(mixed $value): string {
        $json = json_encode(
            $value,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        );

        return \html_writer::tag('pre', s($json === false ? 'null' : $json));
    }
}
