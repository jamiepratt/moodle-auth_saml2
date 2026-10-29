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

/**
 * Standalone synthetic IdP endpoint, reachable only through the isolated TLS fixture.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.RequireLogin.Missing -- Independent IdP fixture must not bootstrap the SP session.
// phpcs:disable moodle.Files.MoodleInternal.MoodleInternalGlobalState -- Standalone guarded synthetic HTTP endpoint.
if (
    getenv('SAML12_HTTPS') !== '1' || ($_SERVER['SAML12_ENDPOINT'] ?? '') !== '1' ||
        ($_SERVER['HTTP_HOST'] ?? '') !== 'idp.identity.test' || ($_SERVER['HTTPS'] ?? '') !== 'on' ||
        !is_file('/fixture/ready') || !is_file('/var/www/data/saml12.json')
) {
    http_response_code(404);
    exit;
}
require_once(__DIR__ . '/protocol.php');
use auth_saml2\fixture\protocol;

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; form-action https://sp.saml.test; style-src 'unsafe-inline'");
try {
    $config = json_decode(file_get_contents('/var/www/data/saml12.json'), true, 16, JSON_THROW_ON_ERROR);
    if (($config['variant'] ?? '') === 'outage') {
        http_response_code(503);
        exit('Synthetic IdP unavailable');
    }
    $input = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($path === '/pf/federation_metadata.ping') {
        if (($input['PartnerSpId'] ?? '') !== protocol::SP) {
            throw new RuntimeException('Unregistered PartnerSpId');
        }
        header('Content-Type: application/samlmetadata+xml');
        echo protocol::metadata(file_get_contents('/fixture/idp.crt'));
        exit;
    }
    $relay = $input['RelayState'] ?? 'https://sp.saml.test/my/';
    if (!is_string($relay) || strlen($relay) > 2048) {
        throw new RuntimeException('Invalid RelayState');
    }
    if (isset($input['SAMLRequest'])) {
        $binding = $_SERVER['REQUEST_METHOD'] === 'POST' ? 'HTTP-POST' : 'HTTP-Redirect';
        $request = protocol::request($input['SAMLRequest'], $binding);
        $requestid = $request['id'];
    } else if (!empty($config['unsolicited']) && $path === '/idp/startSSO.ping') {
        if (
            ($input['PartnerSpId'] ?? '') !== protocol::SP ||
                !in_array($input['IdpAdapterId'] ?? 'SyntheticAdapter', ['SyntheticAdapter'], true) ||
                !in_array(
                    $input['TargetResource'] ?? '',
                    ['https://sp.saml.test/my/', 'https://sp.saml.test/user/profile.php'],
                    true
                )
        ) {
            throw new RuntimeException('Unregistered launch parameters');
        }
        $relay = $input['TargetResource'];
        $binding = 'unsolicited';
        $requestid = '';
    } else if (isset($input['replay']) && is_file('/var/www/data/saml12-response.xml')) {
        $binding = 'replay';
        $requestid = '';
    } else {
        throw new RuntimeException('Unsolicited login disabled');
    }
    $xml = $binding === 'replay' ? file_get_contents('/var/www/data/saml12-response.xml') :
        protocol::response($requestid, $config['attributes'], $config['variant'], '/fixture');
    if ($binding !== 'replay' && $config['variant'] === 'encrypted') {
        $xml = protocol::encrypt($xml, file_get_contents('/var/www/data/saml12-sp.crt'));
    }
    file_put_contents('/var/www/data/saml12-response.xml', $xml);
    setcookie('SAML12_IDP', 'synthetic-session', ['secure' => true, 'httponly' => true, 'samesite' => 'None', 'path' => '/']);
    $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html><head><title>Synthetic IdP</title></head><body><h1>Synthetic IdP</h1>';
    echo '<p>Binding: ' . $escape($binding) . '</p>';
    echo '<p>Retained IdP session: ' . (isset($_COOKIE['SAML12_IDP']) ? 'yes' : 'no') . '</p>';
    echo '<form method="post" action="' . protocol::ACS . '">';
    echo '<input type="hidden" name="SAMLResponse" value="' . $escape(base64_encode($xml)) . '">';
    echo '<input type="hidden" name="RelayState" value="' . $escape($relay) . '">';
    echo '<button type="submit">Continue to Moodle</button></form></body></html>';
} catch (Throwable $error) {
    http_response_code(400);
    echo htmlspecialchars($error->getMessage(), ENT_QUOTES, 'UTF-8');
}
