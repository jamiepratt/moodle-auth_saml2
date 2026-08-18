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

namespace auth_saml2\privacy;

use advanced_testcase;
use core_privacy\local\metadata\null_provider;

/**
 * Tests the retained Catalyst SAML2 privacy declaration.
 *
 * @package    auth_saml2
 * @copyright  2026 Jamie Pratt
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(provider::class)]
final class provider_test extends advanced_testcase {
    /**
     * SAML attributes are mapped into Moodle core user data, not plugin-owned storage.
     */
    public function test_declares_no_plugin_owned_personal_data(): void {
        $this->assertTrue(is_subclass_of(provider::class, null_provider::class));
        $this->assertSame('privacy:no_data_reason', provider::get_reason());
        $this->assertNotEmpty(get_string(provider::get_reason(), 'auth_saml2'));
    }
}
