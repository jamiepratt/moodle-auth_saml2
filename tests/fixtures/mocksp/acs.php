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

/**
 * Local assertion receiver for synthetic Behat journeys only.
 *
 * @package auth_saml2
 * @copyright 2026 Shipmate
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require(__DIR__ . '/../../../../../config.php');
defined('BEHAT_SITE_RUNNING') || die();
require_login(null, false);
require_once(__DIR__ . '/../../../setup.php');

$encoded = required_param('SAMLResponse', PARAM_RAW);
set_config('mocksp_received', (int) get_config('auth_saml2', 'mocksp_received') + 1, 'auth_saml2');
$document = new DOMDocument();
$document->loadXML(base64_decode($encoded, true), LIBXML_NONET);
$validator = new \SimpleSAML\XML\Validator($document, 'ID', file_get_contents($saml2auth->certcrt));
$assertion = $document->getElementsByTagNameNS(\auth_saml2\idp_request::ASSERTION, 'Assertion')->item(0);
if (!$validator->isNodeValidated($assertion)) {
    throw new RuntimeException('Synthetic assertion signature did not validate.');
}
echo 'Registered SP received a signed assertion.';
