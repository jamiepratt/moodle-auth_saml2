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
$httpport = (int) ($argv[5] ?? 0);
$transferlog = $argv[6] ?? '';
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
for ($requestnumber = 0; $requestnumber < 10; $requestnumber++) {
    $connection = stream_socket_accept($server, 3);
    if ($connection === false) {
        if ($requestnumber === 0) {
            while (($opensslerror = openssl_error_string()) !== false) {
                fwrite(STDERR, $opensslerror . "\n");
            }
            fclose($server);
            exit(2);
        }
        break;
    }
    $requestline = trim((string) fgets($connection));
    $requestheaders = '';
    while (($line = fgets($connection)) !== false && trim($line) !== '') {
        $requestheaders .= $line;
    }
    $path = explode(' ', $requestline)[1] ?? '/';
    $status = '200 OK';
    $extraheaders = 'Content-Type: application/samlmetadata+xml' . "\r\n";
    $body = $metadata;
    if ($path === '/downgrade') {
        $status = '302 Found';
        $extraheaders = "Location: http://localhost:{$httpport}/upgrade\r\n";
        $body = '';
    } else if ($path === '/relative/start') {
        $status = '302 Found';
        $extraheaders = "Location: ../metadata.xml\r\n";
        $body = '';
    } else if ($path === '/absolute') {
        $status = '302 Found';
        $extraheaders = "Location: https://localhost:{$port}/metadata.xml\r\n";
        $body = '';
    } else if ($path === '/cycle-a') {
        $status = '302 Found';
        $extraheaders = "Location: /cycle-b\r\n";
        $body = '';
    } else if ($path === '/cycle-b') {
        $status = '302 Found';
        $extraheaders = "Location: /cycle-a\r\n";
        $body = '';
    }
    if (in_array($path, ['/oversized-chunked', '/oversized-redirect'], true)) {
        $status = $path === '/oversized-redirect' ? '302 Found' : '200 OK';
        $extraheaders = $path === '/oversized-redirect'
            ? "Location: /metadata.xml\r\n"
            : "Content-Type: application/samlmetadata+xml\r\n";
        fwrite($connection, "HTTP/1.1 {$status}\r\n{$extraheaders}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        $total = 8 * 1024 * 1024;
        $sent = 0;
        $chunk = str_repeat('x', 16384);
        while ($sent < $total) {
            $written = @fwrite($connection, dechex(strlen($chunk)) . "\r\n{$chunk}\r\n");
            if ($written === false || $written === 0) {
                break;
            }
            $sent += strlen($chunk);
            if ($transferlog !== '') {
                file_put_contents($transferlog, json_encode(['path' => $path, 'sent' => $sent, 'total' => $total]));
            }
        }
        @fwrite($connection, "0\r\n\r\n");
    } else if ($path === '/oversized-gzip') {
        $body = gzencode(str_repeat('x', 3 * 1024 * 1024));
        $headers = "HTTP/1.1 200 OK\r\nContent-Type: application/samlmetadata+xml\r\n" .
            "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        fwrite($connection, $headers . dechex(strlen($body)) . "\r\n{$body}\r\n0\r\n\r\n");
    } else {
        $headers = "HTTP/1.1 {$status}\r\n{$extraheaders}" .
            'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n";
        fwrite($connection, $headers . $body);
    }
    fclose($connection);
}
fclose($server);
