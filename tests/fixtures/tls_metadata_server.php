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

/**
 * Loopback-only synthetic HTTPS metadata service used by metadata_fetcher_test.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$port = (int) ($argv[2] ?? 0);
$certificate = $argv[3] ?? '';
$privatekey = $argv[4] ?? '';
$metadata = file_get_contents(__DIR__ . '/metadata.xml');
if ($port < 1 || $metadata === false || !is_readable($certificate) || !is_readable($privatekey)) {
    fwrite(STDERR, "Invalid synthetic TLS server arguments.\n");
    exit(1);
}
$context = stream_context_create(['ssl' => [
    'local_cert' => $certificate,
    'local_pk' => $privatekey,
    'allow_self_signed' => true,
    'verify_peer' => false,
]]);
$server = stream_socket_server(
    "tls://127.0.0.1:{$port}",
    $errornumber,
    $errormessage,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
    $context
);
if ($server === false) {
    fwrite(STDERR, "{$errornumber}: {$errormessage}\n");
    exit(1);
}
fwrite(STDOUT, "READY\n");
fflush(STDOUT);
$connection = stream_socket_accept($server, 10);
if ($connection === false) {
    while (($opensslerror = openssl_error_string()) !== false) {
        fwrite(STDERR, $opensslerror . "\n");
    }
    fclose($server);
    exit(2);
}
$requestheaders = '';
while (($line = fgets($connection)) !== false && trim($line) !== '') {
    $requestheaders .= $line;
}
$headers = "HTTP/1.1 200 OK\r\nContent-Type: application/samlmetadata+xml\r\n" .
    'Content-Length: ' . strlen($metadata) . "\r\nConnection: close\r\n\r\n";
fwrite($connection, $headers . $metadata);
fclose($connection);
fclose($server);
