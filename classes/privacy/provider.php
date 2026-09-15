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
 * Privacy Subsystem implementation for auth_saml2.
 *
 * @package    auth_saml2
 * @copyright  2018 Olivier SECRET <olivier.secret@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_saml2\privacy;

/**
 * Describes SAML processing without guessing an owner for browser session state.
 *
 * Session contents have no trustworthy Moodle user-ID index. Moodle explicitly
 * excludes time-limited session contents from request exports. See the Privacy
 * API FAQ at https://moodledev.io/docs/5.2/apis/subsystems/privacy/faq.
 * Core providers own mapped profiles and Moodle events. External IdPs, service
 * providers, browser cookies and diagnostic logs cannot be retrieved by user ID.
 *
 * @copyright  2026 Jamie Pratt
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class provider implements
    \core_privacy\local\metadata\provider,
    \core_privacy\local\request\core_userlist_provider,
    \core_privacy\local\request\plugin\provider {
    /**
     * Describe stored data and external transfers.
     *
     * @param \core_privacy\local\metadata\collection $collection Metadata collection.
     * @return \core_privacy\local\metadata\collection
     */
    public static function get_metadata(
        \core_privacy\local\metadata\collection $collection
    ): \core_privacy\local\metadata\collection {
        $fields = [
            'type' => 'privacy:metadata:store:type',
            'k' => 'privacy:metadata:store:key',
            'value' => 'privacy:metadata:store:value',
            'expire' => 'privacy:metadata:store:expire',
        ];
        $collection->add_database_table('auth_saml2_kvstore', $fields, 'privacy:metadata:store');
        $collection->add_external_location_link('session_store', $fields, 'privacy:metadata:session_store');
        $collection->add_external_location_link('browser', [
            'MDL_SSP_SessID' => 'privacy:metadata:browser:session',
            'MDL_SSP_AuthToken' => 'privacy:metadata:browser:token',
            'MOODLEIDP1_' => 'privacy:metadata:browser:idp',
        ], 'privacy:metadata:browser');
        $collection->add_external_location_link('identity_provider', [
            'request' => 'privacy:metadata:idp:request',
        ], 'privacy:metadata:idp');
        $collection->add_external_location_link('service_provider', [
            'attributes' => 'privacy:metadata:sp:attributes',
        ], 'privacy:metadata:sp');
        $collection->add_external_location_link('diagnostic_logs', [
            'diagnostics' => 'privacy:metadata:logs:diagnostics',
        ], 'privacy:metadata:logs');
        $collection->link_subsystem('core_user', 'privacy:metadata:core_user');
        $collection->add_plugintype_link('logstore', [], 'privacy:metadata:core_log');
        return $collection;
    }

    /**
     * Session tokens and external records cannot be safely mapped to a Moodle user ID.
     *
     * @param int $userid Moodle user ID.
     * @return \core_privacy\local\request\contextlist
     */
    public static function get_contexts_for_userid(int $userid): \core_privacy\local\request\contextlist {
        return new \core_privacy\local\request\contextlist();
    }

    /**
     * Core providers export mapped profiles; excluded sessions and external data are not exported.
     *
     * @param \core_privacy\local\request\approved_contextlist $contextlist Approved contexts.
     */
    public static function export_user_data(\core_privacy\local\request\approved_contextlist $contextlist) {
    }

    /**
     * Do not erase unassociated sessions or external records based on context membership.
     *
     * @param \context $context Approved context.
     */
    public static function delete_data_for_all_users_in_context(\context $context) {
    }

    /**
     * Core providers erase mapped profiles; this request does not invalidate SAML sessions.
     *
     * @param \core_privacy\local\request\approved_contextlist $contextlist Approved contexts.
     */
    public static function delete_data_for_user(\core_privacy\local\request\approved_contextlist $contextlist) {
    }

    /**
     * No reliable user-ID association exists for the excluded or external data.
     *
     * @param \core_privacy\local\request\userlist $userlist Context being discovered.
     */
    public static function get_users_in_context(\core_privacy\local\request\userlist $userlist) {
    }

    /**
     * Context membership cannot authorize guessing ownership of unassociated sessions.
     *
     * @param \core_privacy\local\request\approved_userlist $userlist Approved users.
     */
    public static function delete_data_for_users(\core_privacy\local\request\approved_userlist $userlist) {
    }
}
