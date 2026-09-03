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

/**
 * Testcase class for metadata_fetcher class.
 *
 * @package    auth_saml2
 * @author     Sam Chaffee
 * @copyright  Copyright (c) 2017 Blackboard Inc. (http://www.blackboard.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(metadata_fetcher::class)]
final class metadata_fetcher_test extends \advanced_testcase {
    public function test_fetch_uses_verified_synthetic_https_transport(): void {
        $this->assert_synthetic_tls_fetch_succeeds();
    }

    public function test_fetch_forces_hostname_verification_on_real_tls_connection(): void {
        $this->assert_synthetic_tls_hostname_mismatch_is_rejected();
    }

    public function test_fetch_forces_certificate_verification_on_real_tls_connection(): void {
        $this->assert_synthetic_tls_untrusted_chain_is_rejected();
    }

    public function test_fetch_rejects_https_to_http_to_https_redirect_chain(): void {
        $this->with_synthetic_tls_server('localhost', true, function (string $url, \curl $curl): void {
            $url = str_replace('/metadata.xml', '/downgrade', $url);
            try {
                (new metadata_fetcher())->fetch($url, $curl);
                self::fail('The HTTP redirect hop was followed.');
            } catch (\moodle_exception $exception) {
                self::assertSame(
                    get_string('idpmetadata_httpsrequired', 'auth_saml2'),
                    $exception->getMessage()
                );
            }
        }, true);
    }

    public function test_fetch_follows_relative_https_redirect(): void {
        $this->with_synthetic_tls_server('localhost', true, function (string $url, \curl $curl): void {
            $expected = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
            $url = str_replace('/metadata.xml', '/relative/start', $url);
            self::assertSame($expected, (new metadata_fetcher())->fetch($url, $curl));
        });
    }

    public function test_fetch_follows_absolute_redirect_to_final_https_metadata(): void {
        $this->with_synthetic_tls_server('localhost', true, static function (string $url, \curl $curl): void {
            $expected = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
            $url = str_replace('/metadata.xml', '/absolute', $url);
            self::assertSame($expected, (new metadata_fetcher())->fetch($url, $curl));
        });
    }

    public function test_fetch_rejects_redirect_cycle(): void {
        $this->with_synthetic_tls_server('localhost', true, function (string $url, \curl $curl): void {
            $url = str_replace('/metadata.xml', '/cycle-a', $url);
            $this->expectException(\moodle_exception::class);
            (new metadata_fetcher())->fetch($url, $curl);
        });
    }

    public function test_fetch_aborts_oversized_chunked_response_during_transfer(): void {
        global $CFG, $DB;

        $this->resetAfterTest();
        $active = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        $setting = new admin\setting_idpmetadata();
        self::assertSame('', $setting->write_setting($active));
        $livefile = $CFG->dataroot . '/saml2/' . md5('xml') . '.idp.xml';
        $before = [
            'config' => get_config('auth_saml2', 'idpmetadata'),
            'approved' => get_config('auth_saml2', 'metadataapproved'),
            'records' => $DB->get_records('auth_saml2_idps', null, 'id'),
            'livehash' => hash_file('sha256', $livefile),
        ];
        $this->with_synthetic_tls_server(
            'localhost',
            true,
            static function (string $url, \curl $curl, string $transferlog) use ($before, $livefile, $DB): void {
                $url = str_replace('/metadata.xml', '/oversized-chunked', $url);
                $setting = new admin\setting_idpmetadata(
                    static fn(string $target): string => (new metadata_fetcher())->fetch($target, $curl)
                );
                self::assertSame(get_string('metadatafetchtoolarge', 'auth_saml2'), $setting->write_setting($url));
                $transfer = self::wait_for_transfer_log($transferlog);
                self::assertSame('/oversized-chunked', $transfer['path']);
                self::assertGreaterThan(metadata_fetcher::MAX_METADATA_BYTES, $transfer['sent']);
                self::assertLessThan($transfer['total'], $transfer['sent']);
                self::assertSame($before['config'], get_config('auth_saml2', 'idpmetadata'));
                self::assertSame($before['approved'], get_config('auth_saml2', 'metadataapproved'));
                self::assertEquals($before['records'], $DB->get_records('auth_saml2_idps', null, 'id'));
                self::assertSame($before['livehash'], hash_file('sha256', $livefile));
                self::assertFalse((new metadata_trust_manager())->has_pending());

                $metadataurl = preg_replace('~/oversized-chunked$~', '/metadata.xml', $url);
                self::assertSame(
                    file_get_contents(__DIR__ . '/fixtures/metadata.xml'),
                    (new metadata_fetcher())->fetch($metadataurl, $curl)
                );
            }
        );
    }

    /**
     * Wait for the synthetic server to observe transfer beyond the enforced limit.
     *
     * @param string $transferlog Transfer log path.
     * @return array Transfer details containing path, sent bytes, and total bytes.
     */
    private static function wait_for_transfer_log(string $transferlog): array {
        $deadline = microtime(true) + 2;
        $transfer = null;
        do {
            clearstatcache(true, $transferlog);
            $contents = @file_get_contents($transferlog);
            if (is_string($contents)) {
                $candidate = json_decode($contents, true);
                if (is_array($candidate)) {
                    $transfer = $candidate;
                    if (($transfer['sent'] ?? 0) > metadata_fetcher::MAX_METADATA_BYTES) {
                        break;
                    }
                }
            }
            usleep(10000);
        } while (microtime(true) < $deadline);

        self::assertIsArray($transfer);
        self::assertArrayHasKey('path', $transfer);
        self::assertArrayHasKey('sent', $transfer);
        self::assertArrayHasKey('total', $transfer);
        return $transfer;
    }

    public function test_fetch_rejects_oversized_decoded_compressed_response(): void {
        $this->with_synthetic_tls_server('localhost', true, static function (string $url, \curl $curl): void {
            $url = str_replace('/metadata.xml', '/oversized-gzip', $url);
            try {
                (new metadata_fetcher())->fetch($url, $curl);
                self::fail('Oversized decoded gzip metadata was accepted.');
            } catch (\moodle_exception $exception) {
                self::assertSame(get_string('metadatafetchtoolarge', 'auth_saml2'), $exception->getMessage());
            }
        });
    }

    public function test_fetch_rejects_oversized_redirect_body_before_following_location(): void {
        $this->with_synthetic_tls_server('localhost', true, static function (string $url, \curl $curl): void {
            $url = str_replace('/metadata.xml', '/oversized-redirect', $url);
            try {
                (new metadata_fetcher())->fetch($url, $curl);
                self::fail('A redirect with an oversized body was followed.');
            } catch (\moodle_exception $exception) {
                self::assertSame(get_string('metadatafetchtoolarge', 'auth_saml2'), $exception->getMessage());
            }
        });
    }

    /**
     * Verify a locally trusted certificate while fetching real metadata bytes.
     */
    private function assert_synthetic_tls_fetch_succeeds(): void {
        $this->with_synthetic_tls_server('localhost', true, static function (string $url, \curl $curl): void {
            $expected = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
            $fetcher = new metadata_fetcher();

            self::assertSame($expected, $fetcher->fetch($url, $curl));
            self::assertSame(200, $fetcher->get_curlinfo()['http_code'] ?? 0);
        });
    }

    /**
     * Verify that a trusted certificate for a different host is rejected.
     */
    private function assert_synthetic_tls_hostname_mismatch_is_rejected(): void {
        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage('Metadata fetch failed');
        $this->with_synthetic_tls_server('127.0.0.1', true, static function (string $url, \curl $curl): void {
            (new metadata_fetcher())->fetch($url, $curl);
        });
    }

    /**
     * Verify that an otherwise valid local TLS service is rejected without its CA.
     */
    private function assert_synthetic_tls_untrusted_chain_is_rejected(): void {
        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage('Metadata fetch failed');
        $this->with_synthetic_tls_server('localhost', false, static function (string $url, \curl $curl): void {
            (new metadata_fetcher())->fetch($url, $curl);
        });
    }

    /**
     * Run one request against a disposable loopback-only TLS metadata service.
     *
     * @param string $hostname URL host to verify.
     * @param bool $trustcertificate Whether to trust the synthetic server certificate.
     * @param callable $request Assertion callback receiving URL and cURL client.
     * @param bool $withhttpredirect Whether the TLS service redirects through HTTP.
     */
    private function with_synthetic_tls_server(
        string $hostname,
        bool $trustcertificate,
        callable $request,
        bool $withhttpredirect = false
    ): void {
        $reservation = stream_socket_server('tcp://127.0.0.1:0', $errornumber, $errormessage);
        self::assertIsResource($reservation, $errormessage);
        $address = stream_socket_get_name($reservation, false);
        fclose($reservation);
        self::assertIsString($address);
        $port = (int) substr($address, strrpos($address, ':') + 1);

        $httpreservation = stream_socket_server('tcp://127.0.0.1:0', $errornumber, $errormessage);
        self::assertIsResource($httpreservation, $errormessage);
        $httpaddress = stream_socket_get_name($httpreservation, false);
        fclose($httpreservation);
        self::assertIsString($httpaddress);
        $httpport = (int) substr($httpaddress, strrpos($httpaddress, ':') + 1);

        [$certificate, $privatekey] = $this->create_synthetic_tls_identity();
        $transferlog = make_request_directory() . '/tls-transfer.json';

        $pipes = [];
        $process = proc_open(
            [
                PHP_BINARY,
                '-r',
                'define("MOODLE_INTERNAL", true); require $argv[1];',
                __DIR__ . '/fixtures/tls_metadata_server.php',
                (string) $port,
                $certificate,
                $privatekey,
                (string) $httpport,
                $transferlog,
            ],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        stream_set_timeout($pipes[1], 5);
        $ready = fgets($pipes[1]);
        if ($ready !== "READY\n") {
            $error = stream_get_contents($pipes[2]);
            proc_terminate($process);
            proc_close($process);
            self::fail('Synthetic TLS metadata service did not start: ' . $error);
        }

        $httppipes = [];
        $httpprocess = null;
        if ($withhttpredirect) {
            $httpprocess = proc_open(
                [
                    PHP_BINARY,
                    '-r',
                    'define("MOODLE_INTERNAL", true); require $argv[1];',
                    __DIR__ . '/fixtures/http_redirect_server.php',
                    (string) $httpport,
                    (string) $port,
                ],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $httppipes
            );
            self::assertIsResource($httpprocess);
            fclose($httppipes[0]);
            stream_set_timeout($httppipes[1], 5);
            self::assertSame("READY\n", fgets($httppipes[1]));
        }

        $curl = new \curl(['ignoresecurity' => true]);
        $options = [
            'CURLOPT_NOPROXY' => '*',
            'CURLOPT_SSL_VERIFYPEER' => false,
            'CURLOPT_SSL_VERIFYHOST' => 0,
        ];
        if ($trustcertificate) {
            $options['CURLOPT_CAINFO'] = $certificate;
        } else {
            $options['CURLOPT_CAINFO'] = __DIR__ . '/fixtures/mockidp/mock.crt';
        }
        $curl->setopt($options);

        try {
            $request("https://{$hostname}:{$port}/metadata.xml", $curl, $transferlog);
        } finally {
            if (is_resource($httpprocess)) {
                fclose($httppipes[1]);
                fclose($httppipes[2]);
                $httpstatus = proc_get_status($httpprocess);
                if ($httpstatus['running']) {
                    proc_terminate($httpprocess);
                }
                proc_close($httpprocess);
            }
            fclose($pipes[1]);
            fclose($pipes[2]);
            $status = proc_get_status($process);
            if ($status['running']) {
                proc_terminate($process);
            }
            proc_close($process);
        }
    }

    /**
     * Create a test-only self-signed localhost identity without network or host trust-store dependencies.
     *
     * @return string[] Certificate and key paths.
     */
    private function create_synthetic_tls_identity(): array {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $request = openssl_csr_new(['commonName' => 'localhost'], $key, ['digest_alg' => 'sha256']);
        self::assertNotFalse($request);
        $signed = openssl_csr_sign($request, null, $key, 1, ['digest_alg' => 'sha256'], 1);
        self::assertNotFalse($signed);
        self::assertTrue(openssl_x509_export($signed, $certificatecontents));
        self::assertTrue(openssl_pkey_export($key, $privatekeycontents));

        $directory = make_request_directory();
        $certificate = $directory . '/server.crt';
        $privatekey = $directory . '/server.key';
        self::assertSame(strlen($certificatecontents), file_put_contents($certificate, $certificatecontents));
        self::assertSame(strlen($privatekeycontents), file_put_contents($privatekey, $privatekeycontents));
        return [$certificate, $privatekey];
    }

    public function test_fetch_rejects_http_before_network_access(): void {
        $curl = $this->createMock(\curl::class);
        $curl->expects($this->never())->method('get');

        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage(get_string('idpmetadata_httpsrequired', 'auth_saml2'));

        (new metadata_fetcher())->fetch('http://idp.example.test/metadata', $curl);
    }

    public function test_fetch_metadata_404(): void {
        $url = 'https://idp.test/missing-metadata.xml';
        $curl = $this->createMock(\curl::class);
        $curl->method('get')->with($url, $this->isType('array'))->willReturn('');
        $curl->method('get_info')->willReturn(['http_code' => 404]);
        $curl->method('get_errno')->willReturn(0);

        $fetcher = new metadata_fetcher();

        try {
            $fetcher->fetch($url, $curl);
            // Fail if the exception is not thrown.
            $this->fail();
        } catch (\moodle_exception $e) {
            $this->assertEquals(404, (int) $fetcher->get_curlinfo()['http_code']);
        }
    }

    public function test_fetch_metadata_success(): void {
        $url = 'https://idp.test/metadata.xml';
        $metadata = file_get_contents(__DIR__ . '/fixtures/metadata.xml');
        $this->assertIsString($metadata);

        $curl = $this->createMock(\curl::class);
        $curl->method('get')->with($url, $this->isType('array'))->willReturn($metadata);
        $curl->method('get_info')->willReturn(['http_code' => 200]);
        $curl->method('get_errno')->willReturn(0);

        $fetcher = new metadata_fetcher();

        $result = $fetcher->fetch($url, $curl);
        $this->assertSame($metadata, $result);
        $this->assertEquals(0, (int) $fetcher->get_curlerrorno());
        $this->assertEquals(200, (int) $fetcher->get_curlinfo()['http_code']);
    }

    public function test_fetch_rejects_tls_certificate_verification_failure(): void {
        $url = 'https://idp.test/metadata.xml';
        $curl = $this->createMock(\curl::class);
        $curl->method('get')->with($url, $this->isType('array'))->willReturn('certificate verify failed');
        $curl->method('get_info')->willReturn([]);
        $curl->method('get_errno')->willReturn(60); // CURLE_PEER_FAILED_VERIFICATION.

        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage('Metadata fetch failed: certificate verify failed');

        (new metadata_fetcher())->fetch($url, $curl);
    }

    public function test_fetch_rejects_a_redirect_that_finishes_on_http(): void {
        $url = 'https://idp.test/metadata.xml';
        $curl = $this->createMock(\curl::class);
        $curl->method('get')->willReturn('<xml />');
        $curl->method('get_info')->willReturn([
            'http_code' => 200,
            'url' => 'http://idp.test/metadata.xml',
        ]);
        $curl->method('get_errno')->willReturn(0);

        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage(get_string('idpmetadata_httpsrequired', 'auth_saml2'));

        (new metadata_fetcher())->fetch($url, $curl);
    }

    public function test_fetch_metadata_curlerrorno(): void {
        $url = 'https://fakeurl.localhost';
        $curl = $this->createMock(\curl::class);

        $fetcher = new metadata_fetcher();
        $curl->method('get')->with($url, $this->isType('array'))->willReturn('some bad stuff');
        $curl->method('get_errno')->willReturn(CURLE_READ_ERROR);
        $curl->method('get_info')->willReturn(['http_status' => 503]);

        try {
            $fetcher->fetch($url, $curl);
            // Fail if the exception is not thrown.
            $this->fail();
        } catch (\moodle_exception $e) {
            $this->assertEquals(CURLE_READ_ERROR, (int) $fetcher->get_curlerrorno());
            if (method_exists($this, 'assertStringContainsString')) {
                $this->assertStringContainsString('Metadata fetch failed: some bad stuff', $e->getMessage());
            } else {
                // Maintains Support for Moodle 3.5 - remove when this branch does not support Moodle 3.5 anymore.
                $this->assertContains('Metadata fetch failed: some bad stuff', $e->getMessage());
            }
            $this->assertEquals('some bad stuff', $fetcher->get_curlerror());
        }
    }

    public function test_fetch_reports_transport_size_limit_without_persisting_response(): void {
        $curl = $this->createMock(\curl::class);
        $curl->method('get')->willReturn('Maximum file size exceeded');
        $curl->method('get_info')->willReturn(['http_code' => 200]);
        $curl->method('get_errno')->willReturn(CURLE_FILESIZE_EXCEEDED);

        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage(get_string('metadatafetchtoolarge', 'auth_saml2'));
        (new metadata_fetcher())->fetch('https://idp.example.test/oversized.xml', $curl);
    }

    public function test_fetch_metadata_nohttpstatus(): void {
        $url = 'https://fakeurl.localhost';
        $curl = $this->createMock(\curl::class);

        $fetcher = new metadata_fetcher();
        $curl->method('get')->with($url, $this->isType('array'))->willReturn('');
        $curl->method('get_info')->willReturn([]);
        $curl->method('get_errno')->willReturn(0);

        try {
            $fetcher->fetch($url, $curl);
            // Fail if the exception is not thrown.
            $this->fail();
        } catch (\moodle_exception $e) {
            if (method_exists($this, 'assertStringContainsString')) {
                $this->assertStringContainsString('Metadata fetch failed: Unknown cURL error', $e->getMessage());
            } else {
                // Maintains Support for Moodle 3.5 - remove when this branch does not support Moodle 3.5 anymore.
                $this->assertContains('Metadata fetch failed: Unknown cURL error', $e->getMessage());
            }
        }
    }

    public function test_fetch_ignores_configuration_that_disables_tls_verification(): void {
        global $CFG;

        $this->resetAfterTest(true);

        $options = [
            'CURLOPT_SSL_VERIFYPEER' => true,
            'CURLOPT_SSL_VERIFYHOST' => 2,
            'CURLOPT_PROTOCOLS' => CURLPROTO_HTTPS,
            'CURLOPT_REDIR_PROTOCOLS' => CURLPROTO_HTTPS,
            'CURLOPT_CONNECTTIMEOUT' => 10,
            'CURLOPT_FOLLOWLOCATION' => 0,
            'CURLOPT_MAXREDIRS'      => 0,
            'CURLOPT_TIMEOUT'        => 30,
            'CURLOPT_MAXFILESIZE'    => metadata_fetcher::MAX_METADATA_BYTES,
            'CURLOPT_ENCODING'       => '',
            'CURLOPT_RETURNTRANSFER' => false,
            'CURLOPT_NOBODY'         => false,
        ];
        $url = 'https://fakeurl.localhost';
        if (!is_array($CFG->forced_plugin_settings)) {
            $CFG->forced_plugin_settings = [];
        }
        if (!array_key_exists('auth_saml2', $CFG->forced_plugin_settings)) {
            $CFG->forced_plugin_settings['auth_saml2'] = [];
        }
        $CFG->forced_plugin_settings['auth_saml2']['CURLOPT_SSL_VERIFYPEER'] = 0;
        $CFG->forced_plugin_settings['auth_saml2']['CURLOPT_SSL_VERIFYHOST'] = 0;

        $curl = $this->createMock(\curl::class);

        $fetcher = new metadata_fetcher();

        $curl->expects($this->once())->method('get')->with(
            $url,
            [],
            $this->callback(static function (array $actual) use ($options): bool {
                $callback = $actual['CURLOPT_WRITEFUNCTION'] ?? null;
                unset($actual['CURLOPT_WRITEFUNCTION']);
                return $callback instanceof \Closure && $actual === $options;
            })
        )->willReturn('Some error');
        $curl->method('get_info')->willReturn(['http_code' => 200]);
        $curl->method('get_errno')->willReturn(0);

        $fetcher->fetch($url, $curl);
    }
}
