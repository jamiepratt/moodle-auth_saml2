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
 * Test page for SAML
 *
 * @package    auth_saml2
 * @copyright  Brendan Heywood <brendan@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_login();
require_capability('moodle/site:config', context_system::instance());
require('setup.php');

// Check we are in debug mode to use this tool.
if (!$saml2auth->is_debugging()) {
    throw new \moodle_exception('testdebuggingdisabled', 'auth_saml2');
}

if (!\auth_saml2\api::is_enabled()) {
    throw new \moodle_exception('plugindisabled', 'auth_saml2');
}

$PAGE->set_url(new moodle_url('/auth/saml2/test.php'));
$PAGE->set_course($SITE);

$idp = optional_param('idp', '', PARAM_TEXT);
$logout = optional_param('logout', false, PARAM_BOOL);
$idplogout = optional_param('idplogout', '', PARAM_TEXT);
$testtype = optional_param('testtype', 'login', PARAM_TEXT);
$passive = optional_param('passive', false, PARAM_BOOL);
$passivefail = optional_param('passivefail', false, PARAM_BOOL);
$trylogin = optional_param('login', false, PARAM_BOOL);

if ($testtype === 'passive') {
    $passive = true;
}

if (!empty($idp)) {
    $SESSION->saml2idp = $idp;
}

if (empty($SESSION->saml2idp)) {
    // Specify the default IdP to use.
    $SESSION->saml2idp = reset($saml2auth->metadataentities)->md5entityid;
}

if (!empty($logout)) {
    $SESSION->saml2idp = $idplogout;
}

$auth = new SimpleSAML\Auth\Simple($saml2auth->spname);

if ($logout) {
    $url = new moodle_url('/auth/saml2/test.php');
    $auth->logout(['ReturnTo' => $url->out(false)]);
}

echo $OUTPUT->header();

echo \auth_saml2\output\diagnostic::paragraph('SP name: ', (string) $saml2auth->spname);
echo \auth_saml2\output\diagnostic::paragraph('Which IdP will be used? ', (string) $SESSION->saml2idp);

foreach ($saml2auth->metadataentities as $idpentity) {
    echo \html_writer::empty_tag('hr');
    echo \auth_saml2\output\diagnostic::heading('IDP: ', (string) $idpentity->entityid);
    echo \auth_saml2\output\diagnostic::paragraph('md5: ', (string) $idpentity->md5entityid);
    echo \auth_saml2\output\diagnostic::paragraph('check: ', md5($idpentity->entityid));
}

if (!$auth->isAuthenticated() && $passive) {
    /* Prevent it from calling the missing post redirection. /auth/saml2/sp/module.php/core/postredirect.php */
    $auth->requireAuth([
        'KeepPost' => false,
        'isPassive' => true,
        'ErrorURL' => $CFG->wwwroot . '/auth/saml2/test.php?passivefail=1',
    ]);
} else if (!$auth->isAuthenticated() && $trylogin) {
    $auth->requireAuth([
        'KeepPost' => false,
    ]);
} else if (!$auth->isAuthenticated()) {
    $loginurl = new moodle_url('/auth/saml2/test.php', ['login' => true]);
    $passiveurl = new moodle_url('/auth/saml2/test.php', ['passive' => true]);
    $links = \html_writer::link($loginurl, 'Login') . ' | ' . \html_writer::link($passiveurl, 'isPassive test');
    echo \html_writer::tag('p', 'You are not logged in: ' . $links);
    if ($passivefail) {
        $state = \SimpleSAML\Auth\State::loadExceptionState();
        $exception = $state[\SimpleSAML\Auth\State::EXCEPTION_DATA];
        echo \auth_saml2\output\diagnostic::paragraph('Passive test failed with error: ', $exception->getMessage());
    }
} else {
    echo \html_writer::empty_tag('hr');
    $authenticatedidp = (string) $auth->getAuthData('saml:sp:IdP');
    echo \auth_saml2\output\diagnostic::paragraph('Authed with IdP ', $authenticatedidp);
    echo \auth_saml2\output\diagnostic::json($auth->getAttributes());
    $logouturl = new moodle_url('/auth/saml2/test.php', [
        'logout' => true,
        'idplogout' => md5($authenticatedidp),
    ]);
    echo \html_writer::tag('p', 'You are logged in: ' . \html_writer::link($logouturl, 'Logout'));
}

echo $OUTPUT->footer();
