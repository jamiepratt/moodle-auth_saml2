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
 * This file handles the login process when Moodle is acting as an IDP.
 *
 * @package    auth_saml2
 * @copyright  Catalyst IT
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */


require_once(__DIR__ . '/../../../config.php');

// Trust is checked before login redirects, profile reads, signing, or response output.
$config = get_config('auth_saml2');
if (empty($config->moodleidpenabled)) {
    throw new moodle_exception('moodleidpenabled_error', 'auth_saml2');
}
$relaystate = optional_param('RelayState', '', PARAM_RAW);
if ($_SERVER['REQUEST_METHOD'] !== 'GET' || strlen($relaystate) > 80 || preg_match('/[\\x00-\\x1f\\x7f]/', $relaystate)) {
    throw new moodle_exception('moodleidprequest_error', 'auth_saml2');
}
$request = \auth_saml2\idp_request::from_redirect(
    required_param('SAMLRequest', PARAM_RAW),
    $config,
    $CFG->wwwroot . '/auth/saml2/idp/sso.php'
);
require_login(null, false);
if (isguestuser()) {
    throw new moodle_exception('moodleidpguest_error', 'auth_saml2');
}
require_once($CFG->dirroot . '/auth/saml2/setup.php');
require_once($CFG->dirroot . '/user/profile/lib.php');

$authplugin = get_auth_plugin('saml2');
$userfields = array_merge($authplugin->userfields, $authplugin->get_custom_user_profile_fields());
profile_load_data($USER);
$attributes = ['uid' => $USER->username];
foreach ($userfields as $field) {
    $attributes[$field] = $USER->$field ?? '';
}

$signer = new \SimpleSAML\XML\Signer(['id' => 'ID']);
$signer->loadPrivateKey($saml2auth->certpem, $saml2auth->config->privatekeypass, true);
$signer->loadCertificate($saml2auth->certcrt, true);
$response = \auth_saml2\idp_response::create(
    $request,
    $CFG->wwwroot . '/auth/saml2/idp/metadata.php',
    $USER->email,
    $attributes,
    $signer
);

header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html>';
echo html_writer::start_tag('html');
echo html_writer::tag('head', html_writer::tag('title', 'SSO redirect back'));
echo html_writer::start_tag('body');
echo html_writer::start_tag('form', ['id' => 'frog', 'method' => 'post', 'action' => $request->acs]);
echo html_writer::empty_tag('input', [
    'type' => 'hidden', 'name' => 'SAMLResponse', 'value' => base64_encode($response->saveXML()),
]);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'RelayState', 'value' => $relaystate]);
echo html_writer::end_tag('form');
echo html_writer::tag('script', 'document.getElementById("frog").submit();');
echo html_writer::end_tag('body');
echo html_writer::end_tag('html');
exit;
