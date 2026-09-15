<?php
// This file is part of SAML2 Authentication Plugin
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

namespace auth_saml2;

/**
 * Tests for cleanup of plugin-owned files during uninstall.
 *
 * @package auth_saml2
 * @copyright 2026 Jamie Pratt
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversFunction('xmldb_auth_saml2_uninstall')]
final class uninstall_test extends \advanced_testcase {
    /**
     * Load the same callback entrypoint used by Moodle's plugin uninstaller.
     */
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        require_once($CFG->dirroot . '/auth/saml2/db/uninstall.php');
    }

    /**
     * Uninstall removes synthetic trust files and preserves neighboring stores.
     */
    public function test_uninstall_removes_only_owned_files(): void {
        global $CFG;

        $owned = make_upload_directory('saml2/metadata/nested');
        file_put_contents($CFG->dataroot . '/saml2/sp.pem', 'synthetic private key');
        file_put_contents($CFG->dataroot . '/saml2/sp.crt', 'synthetic certificate');
        file_put_contents($owned . '/idp.xml', 'synthetic metadata');
        $neighbor = make_upload_directory('other-auth');
        file_put_contents($neighbor . '/keep.txt', 'unrelated store');
        file_put_contents($CFG->dataroot . '/keep.txt', 'unrelated root file');

        $this->assertTrue(xmldb_auth_saml2_uninstall());

        $this->assertDirectoryDoesNotExist($CFG->dataroot . '/saml2');
        $this->assertSame('unrelated store', file_get_contents($neighbor . '/keep.txt'));
        $this->assertSame('unrelated root file', file_get_contents($CFG->dataroot . '/keep.txt'));
    }

    /**
     * Links at the owned root are removed without deleting their targets.
     *
     * @param string $type Linked target type.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('linked_root_types')]
    public function test_uninstall_removes_a_linked_root_without_following_it(string $type): void {
        global $CFG;

        $outside = make_upload_directory('unrelated');
        file_put_contents($outside . '/keep.txt', 'outside the owned tree');
        $target = match ($type) {
            'directory' => $outside,
            'file' => $outside . '/keep.txt',
            'dangling' => $outside . '/missing',
        };
        $owned = $CFG->dataroot . '/saml2';
        symlink($target, $owned);
        try {
            $this->assertTrue(xmldb_auth_saml2_uninstall());
            $this->assertFalse(is_link($owned));
            $this->assertSame('outside the owned tree', file_get_contents($outside . '/keep.txt'));
        } finally {
            $this->remove_fixture_links_to($outside);
        }
    }

    /**
     * Nested links do not grant ownership of any linked directory or file.
     */
    public function test_uninstall_does_not_follow_nested_links(): void {
        global $CFG;

        $target = make_upload_directory('unrelated');
        file_put_contents($target . '/keep.txt', 'outside the owned tree');
        $nested = make_upload_directory('saml2/metadata/nested');
        symlink($target, $nested . '/directory-link');
        symlink($target . '/keep.txt', $nested . '/file-link');
        symlink($target . '/missing', $nested . '/dangling-link');

        try {
            $this->assertTrue(xmldb_auth_saml2_uninstall());
            $this->assertDirectoryDoesNotExist($CFG->dataroot . '/saml2');
            $this->assertSame('outside the owned tree', file_get_contents($target . '/keep.txt'));
        } finally {
            $this->remove_fixture_links_to($target);
        }
    }

    /**
     * Targets of links at the plugin-owned root.
     *
     * @return array
     */
    public static function linked_root_types(): array {
        return [
            'directory' => ['directory'],
            'file' => ['file'],
            'dangling' => ['dangling'],
        ];
    }

    /**
     * Missing and empty plugin storage can be cleaned repeatedly.
     */
    public function test_uninstall_is_safe_for_missing_and_empty_storage(): void {
        global $CFG;

        $owned = $CFG->dataroot . '/saml2';
        $this->assertDirectoryDoesNotExist($owned);
        $this->assertTrue(xmldb_auth_saml2_uninstall());
        make_upload_directory('saml2');
        $this->assertTrue(xmldb_auth_saml2_uninstall());
        $this->assertDirectoryDoesNotExist($owned);
        $this->assertTrue(xmldb_auth_saml2_uninstall());
        $this->assertDirectoryDoesNotExist($owned);
    }

    /**
     * Remove fixture links before core's test cleanup, even if a callback renamed them.
     *
     * @param string $target Fixture directory whose links must be removed.
     */
    private function remove_fixture_links_to(string $target): void {
        global $CFG;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($CFG->dataroot, \FilesystemIterator::SKIP_DOTS),
        );
        foreach ($iterator as $entry) {
            if ($entry->isLink()) {
                $destination = $entry->getLinkTarget();
                if ($destination === $target || str_starts_with($destination, $target . '/')) {
                    unlink($entry->getPathname());
                }
            }
        }
    }
}
