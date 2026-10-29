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

namespace auth_saml2;

use auth_saml2\fixture\protocol;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/fixtures/stellantis/protocol.php');

/**
 * Synthetic 2017 configuration/schema migration through the real upgrade function.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversFunction('xmldb_auth_saml2_upgrade')]
final class stellantis_upgrade_test extends \advanced_testcase {
    /**
     * Preserve a synthetic hostname, encrypted key, inline trust and observed mapping.
     */
    public function test_legacy_schema_and_keys_upgrade_without_rotating_trust(): void {
        global $CFG, $DB;
        $this->resetAfterTest();
        require_once($CFG->libdir . '/upgradelib.php');
        require_once($CFG->dirroot . '/auth/saml2/db/upgrade.php');
        require_once($CFG->dirroot . '/auth/saml2/setuplib.php');
        $oldroot = $CFG->wwwroot;
        $CFG->wwwroot = 'https://sp.saml.test';
        try {
            set_config('privatekeypass', get_site_identifier(), 'auth_saml2');
            $auth = new auth();
            self::assertEmpty(create_certificates($auth, false, 30));
            $keyhash = hash_file('sha256', $auth->certpem);
            $certhash = hash_file('sha256', $auth->certcrt);
            $idpkey = openssl_pkey_new(['private_key_bits' => 2048]);
            $csr = openssl_csr_new(['commonName' => 'Synthetic IdP'], $idpkey);
            openssl_x509_export(openssl_csr_sign($csr, null, $idpkey, 30), $idpcert);
            $xml = protocol::metadata($idpcert);
            file_put_contents($CFG->dataroot . '/saml2/idp.xml', $xml);
            chmod($auth->certpem, 0644);
            $dbman = $DB->get_manager();
            $dbman->rename_table(new \xmldb_table('auth_saml2_kvstore'), 'auth_samltwo_kvstore');
            $dbman->drop_table(new \xmldb_table('auth_saml2_idps'));
            $dbman->drop_table(new \xmldb_table('auth_saml2_truststate'));
            $DB->delete_records('config_plugins', ['plugin' => 'auth_saml2']);
            foreach (
                ['version' => 2017081700, 'idpmetadata' => $xml, 'idpmetadatarefresh' => 1,
                'idpattr' => 'uid', 'mdlattr' => 'username', 'autocreate' => 1, 'anyauth' => 0,
                'field_map_firstname' => '', 'field_map_lastname' => '', 'field_map_email' => '',
                'privatekeypass' => get_site_identifier(), 'assertionsconsumerservices' => '', 'groupattr' => ''] as $key => $value
            ) {
                set_config($key, $value, 'auth_saml2');
            }
            ob_start();
            try {
                self::assertTrue(\xmldb_auth_saml2_upgrade(2017081700));
            } finally {
                ob_end_clean();
            }
            self::assertTrue($dbman->table_exists('auth_saml2_kvstore'));
            self::assertTrue($dbman->table_exists('auth_saml2_truststate'));
            self::assertFalse($dbman->table_exists('auth_samltwo_kvstore'));
            self::assertSame($xml, get_config('auth_saml2', 'idpmetadata'));
            self::assertSame('0', get_config('auth_saml2', 'idpmetadatarefresh'));
            self::assertNotFalse(get_config('auth_saml2', 'metadataapproved'));
            self::assertSame($keyhash, hash_file('sha256', $auth->certpem));
            self::assertSame($certhash, hash_file('sha256', $auth->certcrt));
            self::assertSame('sp.saml.test', (new auth())->spname);
            self::assertSame('uid', get_config('auth_saml2', 'idpattr'));
            self::assertSame('', get_config('auth_saml2', 'field_map_email'));
            clearstatcache();
            self::assertSame(0, fileperms($auth->certpem) & 0007);
            self::assertNotFalse(openssl_pkey_get_private(
                file_get_contents($auth->certpem),
                get_config('auth_saml2', 'privatekeypass')
            ));
        } finally {
            $CFG->wwwroot = $oldroot;
            // Restore schema names before Moodle's reset if an earlier upgrade failed.
            $dbman = $DB->get_manager();
            if ($dbman->table_exists('auth_samltwo_kvstore') && !$dbman->table_exists('auth_saml2_kvstore')) {
                $dbman->rename_table(new \xmldb_table('auth_samltwo_kvstore'), 'auth_saml2_kvstore');
            }
        }
    }
}
