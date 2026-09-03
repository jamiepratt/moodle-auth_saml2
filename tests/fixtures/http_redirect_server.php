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
 * Loopback-only HTTP redirect service used to prove downgrade hops are rejected.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$port = (int) ($argv[2] ?? 0);
$tlsport = (int) ($argv[3] ?? 0);
$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errornumber, $errormessage);
if ($server === false) {
    fwrite(STDERR, "{$errornumber}: {$errormessage}\n");
    exit(1);
}
fwrite(STDOUT, "READY\n");
fflush(STDOUT);
$connection = stream_socket_accept($server, 5);
if ($connection !== false) {
    $request = '';
    while (($line = fgets($connection)) !== false && trim($line) !== '') {
        $request .= $line;
    }
    fwrite($connection, "HTTP/1.1 302 Found\r\nLocation: https://localhost:{$tlsport}/metadata.xml\r\n" .
        "Content-Length: 0\r\nConnection: close\r\n\r\n");
    fclose($connection);
}
fclose($server);
