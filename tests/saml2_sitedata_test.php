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

namespace auth_saml2;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * Saml2 site data test.
 *
 * @package     auth_saml2
 * @author      Daniel Thee Roperto <daniel.roperto@catalyst-au.net>
 * @copyright   2018 Catalyst IT Australia {@link http://www.catalyst-au.net}
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(auth::class)]
#[\PHPUnit\Framework\Attributes\CoversClass(event\cert_regenerated::class)]
final class saml2_sitedata_test extends \advanced_testcase {
    /**
     * Anonymous request parameters must not create additional signing identities.
     *
     * @param string $method Request parameter source.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('request_methods')]
    public function test_baseurl_requests_reuse_site_certificates(string $method): void {
        global $CFG, $saml2auth;
        $this->resetAfterTest();
        $this->setUser(0);
        $previousget = $_GET;
        $previouspost = $_POST;
        $previousauth = $saml2auth ?? null;
        $sink = $this->redirectEvents();

        try {
            unset($_GET['baseurl'], $_POST['baseurl']);
            require(__DIR__ . '/../setup.php');
            $sitehost = (new \moodle_url($CFG->wwwroot))->get_host();
            $keyhash = hash_file('sha256', $saml2auth->certpem);
            $certhash = hash_file('sha256', $saml2auth->certcrt);
            $files = scandir($saml2auth->get_saml2_directory());
            self::assertCount(1, $sink->get_events());
            $sink->clear();

            foreach (['https://one.example.test', 'https://two.example.test:8443/path'] as $url) {
                if ($method === 'GET') {
                    $_GET['baseurl'] = $url;
                } else {
                    $_POST['baseurl'] = $url;
                }
                require(__DIR__ . '/../setup.php');
                self::assertSame($sitehost, $saml2auth->spname);
                self::assertSame($keyhash, hash_file('sha256', $saml2auth->certpem));
                self::assertSame($certhash, hash_file('sha256', $saml2auth->certcrt));
                self::assertSame($files, scandir($saml2auth->get_saml2_directory()));
                self::assertCount(0, $sink->get_events());
            }
        } finally {
            $_GET = $previousget;
            $_POST = $previouspost;
            $saml2auth = $previousauth;
            $sink->close();
        }
    }

    /**
     * Both parameter sources accepted by Moodle.
     *
     * @return array
     */
    public static function request_methods(): array {
        return [['GET'], ['POST']];
    }

    /**
     * Refused generation must not produce success audit records on repeated requests.
     */
    public function test_locked_certificates_do_not_emit_regeneration_events(): void {
        global $saml2auth;
        $this->resetAfterTest();
        $this->setUser(0);
        $previousauth = $saml2auth ?? null;
        $sink = $this->redirectEvents();
        set_config('certs_locked', 1, 'auth_saml2');

        try {
            for ($request = 0; $request < 2; $request++) {
                require(__DIR__ . '/../setup.php');
                $this->assertDebuggingCalled();
                self::assertFileDoesNotExist($saml2auth->certpem);
                self::assertFileDoesNotExist($saml2auth->certcrt);
                self::assertCount(0, $sink->get_events());
            }
            set_config('certs_locked', 0, 'auth_saml2');
            require(__DIR__ . '/../setup.php');
            self::assertFileExists($saml2auth->certpem);
            self::assertFileExists($saml2auth->certcrt);
            self::assertCount(1, $sink->get_events());
            self::assertInstanceOf(event\cert_regenerated::class, $sink->get_events()[0]);
        } finally {
            $saml2auth = $previousauth;
            $sink->close();
        }
    }

    public function test_it_creates_the_directory_if_it_does_not_exist(): void {
        global $CFG;

        $expected = "{$CFG->dataroot}/saml2";
        self::assertFalse(file_exists($expected));

        /** @var auth_plugin_saml2 $saml2 */
        $saml2 = get_auth_plugin('saml2');
        self::assertTrue(file_exists($expected));

        rmdir($expected);
        $actual = $saml2->get_saml2_directory();
        self::assertTrue(file_exists($expected));

        self::assertSame($expected, $actual);
    }
    public function test_it_emits_an_event_when_saml_certificate_regenerated(): void {
        global $CFG, $DB;
        $this->resetAfterTest();
        // To test event is emitted to logstore table.
        $this->preventResetByRollback();
        set_config('enabled_stores', 'logstore_standard', 'tool_log');
        set_config('buffersize', 0, 'logstore_standard');

        // The cert files don't exist now so including setup.php here will regenerate them.
        require($CFG->dirroot . '/auth/saml2/setup.php');

        // Get log records and check for presence of the cert_regenerated event.
        $logmanger = get_log_manager();
        $readers = $logmanger->get_readers('\core\log\reader');
        $reader = reset($readers);
        $eventarray = $reader->get_events_select("eventname = ?", ['\auth_saml2\event\cert_regenerated'], 'id ASC', 0, 0);
        self::assertEquals(1, count($eventarray));

        $event = reset($eventarray);
        $eventdata = $event->get_data();
        $expecteddata = [
            'reason' => "= Missing cert pem file! =\n= Missing cert crt file! = \nNow regenerating saml2 certificates...",
        ];
        self::assertEquals($expecteddata['reason'], $eventdata['other']['reason']);
        self::assertEquals('\auth_saml2\event\cert_regenerated', $eventdata['eventname']);
    }
}
