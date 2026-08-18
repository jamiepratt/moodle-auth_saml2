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

use core\plugin_manager;

/**
 * Moodle compatibility metadata tests.
 *
 * @package    auth_saml2
 * @copyright  2026 Shipmate
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @coversNothing
 */
final class compatibility_test extends \advanced_testcase {
    /**
     * The maintained branch explicitly supports Moodle 5.2.
     */
    public function test_moodle_502_is_explicitly_supported(): void {
        $plugin = plugin_manager::instance()->get_plugin_info('auth_saml2');

        $this->assertNotNull($plugin);
        $this->assertSame([502, 502], $plugin->pluginsupported);
        $this->assertSame(
            plugin_manager::VERSION_SUPPORTED,
            plugin_manager::instance()->check_explicitly_supported($plugin, 502),
        );
    }
}
