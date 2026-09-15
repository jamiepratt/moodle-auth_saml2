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

namespace auth_saml2\privacy;

use advanced_testcase;
use core_privacy\manager;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\contextlist_collection;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\request\userlist_collection;
use core_privacy\local\request\writer;
use SimpleSAML\Configuration;
use SimpleSAML\Session;
use SimpleSAML\Store\StoreFactory;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../../vendor/autoload.php');

/**
 * Tests the retained Catalyst SAML2 privacy declaration.
 *
 * @package    auth_saml2
 * @copyright  2026 Jamie Pratt
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(provider::class)]
final class provider_test extends advanced_testcase {
    /**
     * The manager reports storage, cookies and external transfers instead of no data.
     */
    public function test_metadata_describes_processed_data(): void {
        global $saml2auth;
        $this->resetAfterTest();
        $manager = new class extends manager {
            /**
             * Restrict this manager request to the SAML provider.
             *
             * @return array
             */
            protected function get_component_list(): array {
                return ['auth_saml2'];
            }
        };
        $metadata = $manager->get_metadata_for_components();
        $this->assertArrayHasKey('auth_saml2', $metadata);
        $items = [];
        foreach ($metadata['auth_saml2']->get_collection() as $item) {
            $items[$item->get_name()] = $item;
            $this->assertNotEmpty(get_string($item->get_summary(), 'auth_saml2'));
            foreach ($item->get_privacy_fields() as $description) {
                $this->assertNotEmpty(get_string($description, 'auth_saml2'));
            }
        }
        foreach (
            ['auth_saml2_kvstore', 'session_store', 'browser', 'identity_provider', 'service_provider',
                'core_user', 'logstore'] as $name
        ) {
            $this->assertArrayHasKey($name, $items);
        }
        $saml2auth = new \auth_saml2\auth();
        // Read the plugin configuration in a native fixture, not a web entrypoint.
        // @codingStandardsIgnoreLine
        require(__DIR__ . '/../../config/config.php');
        $this->assertSame([
            $config['session.cookie.name'], $config['session.authtoken.cookiename'], 'MOODLEIDP1_',
        ], array_keys($items['browser']->get_privacy_fields()));
        $this->assertSame(0, $config['session.cookie.lifetime']);
        $this->assertTrue($manager->component_is_compliant('auth_saml2'));
        $this->assertTrue(is_subclass_of(provider::class, \core_privacy\local\request\core_userlist_provider::class));
    }

    /**
     * Real stored authentication attributes cannot be safely selected by an unrelated Moodle user ID.
     *
     * @param string $storeclass Selected supported store.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('store_provider')]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function test_manager_preserves_unassociated_sessions(string $storeclass): void {
        global $CFG;
        $this->resetAfterTest();
        $_SERVER['REQUEST_URI'] = '/auth/saml2/login.php';
        $CFG->auth_saml2_redis_server = getenv('AUTH_SAML2_REDIS_STORE_TEST_SERVER');
        Configuration::setPreLoadedConfig(Configuration::loadFromArray([
            'store.type' => $storeclass,
            'session.duration' => 600,
            'session.cookie.secure' => false,
            'session.cookie.samesite' => 'Lax',
            'secretsalt' => 'synthetic-privacy-test-only',
            'logging.handler' => 'errorlog',
        ]));
        StoreFactory::clearInternalState();
        $store = StoreFactory::getInstance($storeclass);
        $handler = \SimpleSAML\SessionHandler::getSessionHandler();
        $users = [];
        $keys = [];
        try {
            foreach (['first', 'second'] as $name) {
                $users[] = $this->getDataGenerator()->create_user(['username' => $name, 'email' => 'shared@example.test']);
                Session::clearInternalState();
                Session::useTransientSession();
                $session = Session::getSessionFromRequest();
                $session->doLogin('synthetic-idp', [
                    'Attributes' => ['mail' => ['shared@example.test'], 'uid' => [$name]],
                    'saml:sp:NameID' => $name,
                ]);
                $state = ['Attributes' => ['mail' => ['shared@example.test']]];
                \SimpleSAML\Auth\State::saveState($state, 'synthetic-stage');
                // Exercise actual store serialization without browser headers/session IDs in the CLI fixture.
                $key = bin2hex(random_bytes(32));
                $keys[] = $key;
                $store->set('session', $key, $session, time() + 600);
                $session->save();
            }
            $manager = new class extends manager {
                /**
                 * Restrict this manager request to the SAML provider.
                 *
                 * @return array
                 */
                protected function get_component_list(): array {
                    return ['auth_saml2'];
                }
            };
            foreach ($users as $user) {
                $contexts = $manager->get_contexts_for_userid($user->id);
                foreach ($contexts as $contextlist) {
                    $this->assertCount(0, $contextlist);
                }
                $approved = new contextlist_collection($user->id);
                $approved->add_contextlist(new approved_contextlist($user, 'auth_saml2', [
                    \context_system::instance()->id, \context_user::instance($user->id)->id,
                ]));
                writer::reset();
                $manager->export_user_data($approved);
                $this->assertFalse(writer::with_context(\context_system::instance())->has_any_data_in_any_context());
                $manager->delete_data_for_user($approved);
            }
            $system = \context_system::instance();
            foreach ($manager->get_users_in_context($system) as $userlist) {
                $this->assertCount(0, $userlist);
            }
            $approvedusers = new userlist_collection($system);
            $approvedusers->add_userlist(new approved_userlist($system, 'auth_saml2', [$users[0]->id]));
            $manager->delete_data_for_users_in_context($approvedusers);
            $manager->delete_data_for_all_users_in_context($system);
            foreach ($keys as $index => $key) {
                $session = $handler->loadSession($key);
                $this->assertInstanceOf(Session::class, $session);
                $this->assertSame([$users[$index]->username], $session->getAuthData('synthetic-idp', 'Attributes')['uid']);
                $this->assertSame([$users[$index]->email], $session->getAuthData('synthetic-idp', 'Attributes')['mail']);
                $this->assertNotEmpty($session->getDataOfType('\\SimpleSAML\\Auth\\State'));
            }
            // Explicit token invalidation affects one session, not the other identity.
            $store->delete('session', $keys[0]);
            $this->assertNull($handler->loadSession($keys[0]));
            $this->assertTrue($store->get('session', $keys[1])->isValid('synthetic-idp'));
            $session = $handler->loadSession($keys[1]);
            $session->setAuthorityExpire('synthetic-idp', -1);
            $this->assertFalse($session->isValid('synthetic-idp'));
            $session->save();
            $store->set('session', $keys[1], $session, time() - 1);
            $this->assertNull($handler->loadSession($keys[1]));
        } finally {
            foreach ($keys as $key) {
                $store->delete('session', $key);
            }
            Session::clearInternalState();
            StoreFactory::clearInternalState();
            Configuration::clearInternalState();
        }
    }

    /**
     * Default and administrator-selected bundled stores.
     *
     * @return array
     */
    public static function store_provider(): array {
        return [
            'database' => [\auth_saml2\store::class],
            'redis' => [\auth_saml2\redis_store::class],
        ];
    }
}
