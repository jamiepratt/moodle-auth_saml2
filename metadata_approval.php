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
 * Review and activate staged IdP metadata.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../../config.php');

use auth_saml2\admin\setting_idpmetadata;
use auth_saml2\metadata_trust_manager;

require_login();
$context = context_system::instance();
require_capability('moodle/site:config', $context);

$url = new moodle_url('/auth/saml2/metadata_approval.php');
$settingsurl = new moodle_url('/admin/settings.php', ['section' => 'authsettingsaml2']);
$PAGE->set_url($url);
$PAGE->set_context($context);
$PAGE->set_title(get_string('metadataapproval', 'auth_saml2'));
$PAGE->set_heading(get_string('metadataapproval', 'auth_saml2'));

$manager = new metadata_trust_manager();
$manager->recover();
if (optional_param('confirm', 0, PARAM_BOOL)) {
    $requestsesskey = optional_param('sesskey', '', PARAM_RAW);
    if ($requestsesskey === '' || !confirm_sesskey($requestsesskey)) {
        redirect($url, get_string('invalidsesskey', 'error'), null, \core\output\notification::NOTIFY_ERROR);
    }
    if (!optional_param('outofband', 0, PARAM_BOOL)) {
        redirect(
            $url,
            get_string('metadataapprovalconfirmationrequired', 'auth_saml2'),
            null,
            \core\output\notification::NOTIFY_ERROR
        );
    }
    $authority = required_param('authority', PARAM_ALPHA);
    $expectedfingerprint = required_param('proposalfingerprint', PARAM_ALPHANUM);
    (new setting_idpmetadata())->approve_pending($USER->id, $authority, true, $expectedfingerprint);
    redirect($settingsurl, get_string('metadataapprovalsuccess', 'auth_saml2'));
}

echo $OUTPUT->header();
if (!$manager->has_pending()) {
    echo $OUTPUT->notification(get_string('idpmetadata_nopending', 'auth_saml2'), 'info');
    echo $OUTPUT->continue_button($settingsurl);
    echo $OUTPUT->footer();
    exit;
}

$review = $manager->get_pending_review();
$summary = $review['summary'];
echo $OUTPUT->notification(get_string('metadataapprovalwarning', 'auth_saml2'), 'warning');
echo html_writer::tag('p', get_string('metadataapprovalsummary', 'auth_saml2', (object) [
    'signingkeys' => $summary['signingkeys'] ? get_string('yes') : get_string('no'),
    'endpoints' => $summary['endpoints'] ? get_string('yes') : get_string('no'),
    'entities' => $summary['entities'] ? get_string('yes') : get_string('no'),
    'sources' => $summary['sources'] ? get_string('yes') : get_string('no'),
]));
echo html_writer::tag('h3', get_string('metadataapprovalfingerprint', 'auth_saml2'));
echo html_writer::tag('p', html_writer::tag('code', s($review['proposalfingerprint'])));
foreach ($review['details'] as $source) {
    $sourcetype = $source['source'] === 'xml'
        ? get_string('metadataapprovalsourceinline', 'auth_saml2')
        : get_string('metadataapprovalsourceremote', 'auth_saml2');
    echo html_writer::tag('h3', get_string('metadataapprovalsource', 'auth_saml2'));
    echo html_writer::tag('p', s($sourcetype) . ': ' . html_writer::tag('code', s($source['source'])));
    foreach ($source['entities'] as $entity) {
        echo html_writer::tag('h4', get_string('metadataapprovalentity', 'auth_saml2'));
        echo html_writer::tag('p', html_writer::tag('code', s($entity['entityid'])));
        foreach ($entity['signingkeys'] as $key) {
            echo html_writer::tag('p', s(get_string('metadataapprovalsigningkey', 'auth_saml2')) . ': ' .
                html_writer::tag('code', s($key)));
        }
        foreach ($entity['endpoints'] as $endpoint) {
            $endpointdetails = [
                $endpoint['type'],
                $endpoint['location'],
                $endpoint['responselocation'],
                get_string('metadataapprovalbinding', 'auth_saml2') . ': ' . $endpoint['binding'],
                get_string('metadataapprovalindex', 'auth_saml2') . ': ' .
                    ($endpoint['index'] === '' ? get_string('metadataapprovalnotset', 'auth_saml2') : $endpoint['index']),
                get_string('metadataapprovalisdefault', 'auth_saml2') . ': ' .
                    ($endpoint['isdefault'] === ''
                        ? get_string('metadataapprovalnotset', 'auth_saml2')
                        : $endpoint['isdefault']),
            ];
            $endpointdetails = array_filter($endpointdetails, static fn(string $value): bool => $value !== '');
            echo html_writer::tag('p', s(get_string('metadataapprovalendpoint', 'auth_saml2')) . ': ' .
                html_writer::tag('code', s(implode(' | ', $endpointdetails))));
        }
    }
}

echo html_writer::start_tag('form', ['method' => 'post', 'action' => $url]);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'sesskey', 'value' => sesskey()]);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'confirm', 'value' => 1]);
echo html_writer::empty_tag('input', [
    'type' => 'hidden',
    'name' => 'proposalfingerprint',
    'value' => $review['proposalfingerprint'],
]);
echo html_writer::label(get_string('metadataapprovalauthority', 'auth_saml2'), 'id_authority');
echo html_writer::select([
    metadata_trust_manager::AUTHORITY_OWNER => get_string('metadataapprovalowner', 'auth_saml2'),
    metadata_trust_manager::AUTHORITY_DELEGATE => get_string('metadataapprovaldelegate', 'auth_saml2'),
], 'authority', metadata_trust_manager::AUTHORITY_OWNER, false, ['id' => 'id_authority']);
echo html_writer::div(
    html_writer::checkbox('outofband', 1, false, get_string('metadataapprovaloutofband', 'auth_saml2')),
    'mt-3'
);
echo html_writer::div(
    html_writer::empty_tag('input', [
        'type' => 'submit',
        'class' => 'btn btn-danger',
        'value' => get_string('metadataapprovalactivate', 'auth_saml2'),
    ]),
    'mt-3'
);
echo html_writer::end_tag('form');
echo $OUTPUT->footer();
