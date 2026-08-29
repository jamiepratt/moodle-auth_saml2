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

namespace auth_saml2\event;

use core\event\base;

/**
 * Audit event for a security-relevant IdP metadata change.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class metadata_change_detected extends base {
    /**
     * Return the event name.
     *
     * @return string
     */
    public static function get_name() {
        return get_string('eventmetadatachangedetected', 'auth_saml2');
    }

    /**
     * Return the event description.
     *
     * @return string
     */
    public function get_description() {
        return "A security-relevant IdP metadata change was staged as '{$this->other['proposedfingerprint']}'.";
    }

    /**
     * Initialise event data.
     */
    protected function init() {
        $this->data['crud'] = 'c';
        $this->data['edulevel'] = self::LEVEL_OTHER;
        $this->context = \context_system::instance();
    }
}
