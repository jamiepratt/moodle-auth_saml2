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

use SimpleXMLElement;

defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/../locallib.php');

/**
 * Tests for SAML
 *
 * @package    auth_saml2
 * @copyright  Brendan Heywood <brendan@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversFunction('auth_saml2_get_sp_metadata')]
#[\PHPUnit\Framework\Attributes\CoversFunction('create_certificates')]
final class locallib_test extends \advanced_testcase {
    /**
     * Published metadata and login configuration use the administrator's site identity.
     *
     * @param string $method Request parameter source.
     * @param string $wwwroot Configured Moodle URL, including a subdirectory.
     * @param string $entityid Optional administrator-configured entity ID.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('site_identities')]
    public function test_baseurl_cannot_change_metadata_or_login_configuration(
        string $method,
        string $wwwroot,
        string $entityid
    ): void {
        global $CFG, $saml2auth, $saml2config;
        require_once(__DIR__ . '/../setuplib.php');
        $this->resetAfterTest();
        $this->setUser(0);
        $previousroot = $CFG->wwwroot;
        $previousget = $_GET;
        $previouspost = $_POST;
        $previousauth = $saml2auth ?? null;
        $previousconfig = $saml2config ?? null;
        $untrustedurl = 'https://unregistered.example.test/other';

        try {
            \SimpleSAML\Configuration::clearInternalState();
            $CFG->wwwroot = $wwwroot;
            unset($_GET['baseurl'], $_POST['baseurl']);
            if ($method === 'GET') {
                $_GET['baseurl'] = $untrustedurl;
            } else {
                $_POST['baseurl'] = $untrustedurl;
            }
            $this->getDataGenerator()->get_plugin_generator('auth_saml2')->create_idp_entity([], false);
            set_config('spentityid', $entityid, 'auth_saml2');
            require(__DIR__ . '/../setup.php');
            // phpcs:ignore moodle.Files.RequireLogin.Missing -- PHPUnit loads configuration, not a web entrypoint.
            require(__DIR__ . '/../config/config.php');
            self::assertSame($wwwroot . '/auth/saml2/sp/', $config['baseurlpath']);
            self::assertSame($wwwroot . '/auth/saml2/sp/', $config['application']['baseURL']);

            $expectedid = $entityid ?: $wwwroot . '/auth/saml2/sp/metadata.php';
            $source = \SimpleSAML\Auth\Source::getById($saml2auth->spname);
            self::assertSame($expectedid, $source->getEntityId());

            // The legacy helper argument must not rewrite the shared metadata cache either.
            $rawxml = auth_saml2_get_sp_metadata($untrustedurl);
            $xml = new SimpleXMLElement($rawxml);
            $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
            self::assertSame($expectedid, (string)$xml['entityID']);
            $acs = $xml->xpath('//md:AssertionConsumerService');
            self::assertNotEmpty($acs);
            foreach ($acs as $endpoint) {
                self::assertSame(
                    $wwwroot . '/auth/saml2/sp/saml2-acs.php/' . $saml2auth->spname,
                    (string)$endpoint['Location']
                );
            }
            $logout = $xml->xpath('//md:SingleLogoutService');
            self::assertNotEmpty($logout);
            foreach ($logout as $endpoint) {
                self::assertSame(
                    $wwwroot . '/auth/saml2/sp/saml2-logout.php/' . $saml2auth->spname,
                    (string)$endpoint['Location']
                );
            }
            self::assertStringNotContainsString($untrustedurl, $rawxml);
            self::assertSame($rawxml, auth_saml2_get_sp_metadata());
        } finally {
            $CFG->wwwroot = $previousroot;
            $_GET = $previousget;
            $_POST = $previouspost;
            $saml2auth = $previousauth;
            $saml2config = $previousconfig;
            \SimpleSAML\Configuration::clearInternalState();
        }
    }

    /**
     * Both request methods and default/custom entity IDs on subdirectory sites.
     *
     * @return array
     */
    public static function site_identities(): array {
        return [
            ['GET', 'https://site.example.test:8443/training', ''],
            ['POST', 'http://site.example.test/training', 'urn:example:configured-sp'],
        ];
    }

    /**
     * Regression test for Issue 132.
     */
    public function test_it_can_initialise_more_than_once(): void {
        global $CFG, $DB;
        $this->resetAfterTest(true);

        // Add a fake IdP.
        $DB->insert_record('auth_saml2_idps', [
            'metadataurl' => 'http://www.example.com',
            'entityid'    => 'http://www.example.com',
            'name'        => 'Test IdP',
            'activeidp'   => 1]);

        for ($i = 0; $i < 3; $i++) {
            require($CFG->dirroot . '/auth/saml2/setup.php');
            $xml = auth_saml2_get_sp_metadata();
            self::assertNotNull($xml);
            self::resetAllData(false);
        }
    }

    public function test_auth_saml2_sp_metadata(): void {
        global $CFG;

        $this->resetAfterTest();

        // Set just enough config to generate SP metadata.
        $email = 'test@test.com';
        $url = 'http://www.example.com';
        set_config('supportemail', $email);
        set_config('idpmetadata', $url, 'auth_saml2');
        set_config('idpentityids', json_encode([$url => $url]), 'auth_saml2');

        require($CFG->dirroot . '/auth/saml2/setup.php');

        $rawxml = auth_saml2_get_sp_metadata();

        $xml = new SimpleXMLElement($rawxml);
        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('mdui', 'urn:oasis:names:tc:SAML:metadata:ui');

        $contact = $xml->xpath('//md:EntityDescriptor/md:ContactPerson');
        $this->assertNotNull($contact);
    }

    /**
     * If locked do not generate the cert, if unlocked then generate the cert.
     */
    public function test_setup_no_cert_generate_if_locked(): void {
        $this->resetAfterTest();
        $auth = get_auth_plugin('saml2');
        set_config('certs_locked', 1, 'auth_saml2');

        // Make sure we have no files.
        $crt = file_exists($auth->certcrt);
        if ($crt) {
            unlink($auth->certcrt);
        }
        $this->assertFalse($crt);

        // Call setup.php and see that it doesn't generate a cert.
        require(dirname(__FILE__) . '/../setup.php');
        $this->assertDebuggingCalled();
        $crt = file_exists($auth->certcrt);
        $this->assertFalse($crt);

        // Set config unlocked.
        set_config('certs_locked', 0, 'auth_saml2');

        // Call setup.php and see that it generates the certificate.
        require(dirname(__FILE__) . '/../setup.php');
        $crt = file_exists($auth->certcrt);
        $this->assertTrue($crt);
    }

    /**
     * If locked and we try to generate certs, throw an exception and do not generate the certs.
     */
    public function test_create_certificates_if_locked(): void {
        $this->resetAfterTest();
        $auth = get_auth_plugin('saml2');
        set_config('certs_locked', 1, 'auth_saml2');

        // Call the create_certificates function directly to assert that
        // it throws an exception and does not generate a cert.
        try {
            create_certificates($auth);
            // Fail if the exception is not thrown.
            $this->fail();
        } catch (\saml2_exception $e) {
            $this->assertFalse(file_exists($auth->certcrt));
        }
    }

    public function test_create_certificates_publishes_private_key_owner_only_without_changing_directory(): void {
        $this->resetAfterTest();
        require_once(__DIR__ . '/../setuplib.php');
        $auth = get_auth_plugin('saml2');
        $directory = dirname($auth->certpem);
        $directorymode = fileperms($directory) & 07777;
        chmod($directory, 0750);
        @unlink($auth->certpem);
        @unlink($auth->certcrt);
        $oldmask = umask(0000);

        try {
            create_certificates($auth);
        } finally {
            umask($oldmask);
        }

        clearstatcache(true, $auth->certpem);
        self::assertFileExists($auth->certpem);
        self::assertSame(0600, fileperms($auth->certpem) & 0777);
        self::assertSame(0750, fileperms($directory) & 07777);
        chmod($directory, $directorymode);
    }

    public function test_create_certificates_can_publish_for_an_explicit_trusted_setgid_group(): void {
        $this->resetAfterTest();
        require_once(__DIR__ . '/../setuplib.php');
        $auth = get_auth_plugin('saml2');
        $directory = dirname($auth->certpem);
        $directorymode = fileperms($directory) & 07777;
        $trustedgroup = filegroup($directory);
        self::assertIsInt($trustedgroup);
        self::assertTrue(chmod($directory, 02750));
        @unlink($auth->certpem);
        @unlink($auth->certcrt);

        try {
            self::assertEmpty(create_certificates($auth, false, 3650, $trustedgroup));
            clearstatcache(true, $auth->certpem);
            self::assertFileExists($auth->certpem);
            self::assertSame($trustedgroup, filegroup($auth->certpem));
            self::assertSame(0640, fileperms($auth->certpem) & 0777);
        } finally {
            chmod($directory, $directorymode);
        }
    }

    public function test_create_certificates_rejects_group_access_without_a_matching_setgid_directory(): void {
        $this->resetAfterTest();
        require_once(__DIR__ . '/../setuplib.php');
        $auth = get_auth_plugin('saml2');
        $directory = dirname($auth->certpem);
        $directorymode = fileperms($directory) & 07777;
        $directorygroup = filegroup($directory);
        self::assertIsInt($directorygroup);
        self::assertTrue(chmod($directory, 0750));
        @unlink($auth->certpem);
        @unlink($auth->certcrt);

        try {
            self::assertSame(
                get_string('nullprivatecert', 'auth_saml2'),
                create_certificates($auth, false, 3650, $directorygroup)
            );
            self::assertFileDoesNotExist($auth->certpem);
            self::assertFileDoesNotExist($auth->certcrt);
        } finally {
            chmod($directory, $directorymode);
        }
    }
}
