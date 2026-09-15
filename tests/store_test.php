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

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * Database store expiry behavior.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(store::class)]
final class store_test extends \advanced_testcase {
    /**
     * Cleanup uses the same inclusive boundary as access expiry.
     */
    public function test_cleanup_removes_inaccessible_rows_only(): void {
        global $DB;
        $this->resetAfterTest();
        $store = new store();
        $store->set('session', 'active', ['mail' => ['active@example.test']], time() + 600);
        $store->set('session', 'expired', ['mail' => ['expired@example.test']], time());
        $this->assertNull($store->get('session', 'expired'));
        $store->delete_expired();
        $this->assertFalse($DB->record_exists('auth_saml2_kvstore', ['k' => 'expired']));
        $this->assertSame(['mail' => ['active@example.test']], $store->get('session', 'active'));
    }
}
