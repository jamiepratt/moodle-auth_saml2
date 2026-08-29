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
 * Audit event for explicit activation of staged IdP metadata.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class metadata_change_approved extends base {
    /**
     * Return the event name.
     *
     * @return string
     */
    public static function get_name() {
        return get_string('eventmetadatachangeapproved', 'auth_saml2');
    }

    /**
     * Return the event description.
     *
     * @return string
     */
    public function get_description() {
        return "User '{$this->userid}' approved IdP metadata '{$this->other['approvedfingerprint']}' " .
            "as '{$this->other['authority']}' after out-of-band IdP confirmation.";
    }

    /**
     * Initialise event data.
     */
    protected function init() {
        $this->data['crud'] = 'u';
        $this->data['edulevel'] = self::LEVEL_OTHER;
        $this->context = \context_system::instance();
    }
}
