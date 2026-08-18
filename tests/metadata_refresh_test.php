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

namespace auth_saml2;

use auth_saml2\admin\setting_idpmetadata;
use auth_saml2\task\metadata_refresh;

/**
 * Testcase class for metadata_refresh task class.
 *
 * @package    auth_saml2
 * @author     Sam Chaffee
 * @copyright  Copyright (c) 2017 Blackboard Inc. (http://www.blackboard.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class metadata_refresh_test extends \advanced_testcase {
    /**
     * Set up
     */
    public function setUp(): void {
        parent::setUp();
        $this->resetAfterTest(true);
    }

    public function test_metadata_refresh_disabled(): void {
        set_config('idpmetadatarefresh', 0, 'auth_saml2');
        set_config('idpmetadata', 'http://somefakeidpurl.local', 'auth_saml2');

        $refreshtask = new metadata_refresh();
        $this->expectOutputString('IdP metadata refresh is not configured. ' .
            "Enable it in the auth settings or disable this scheduled task\n");
        self::assertFalse($refreshtask->execute());
    }

    public function test_metadata_refresh_idpmetadata_non_url(): void {
        $randomxml = <<<XML
<?xml version="1.0" encoding="utf-8"?>
<somexml>yada</somexml>
XML;
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', $randomxml, 'auth_saml2');

        $refreshtask = new metadata_refresh();

        $this->expectOutputString('IdP metadata config not a URL, nothing to refresh.' . "\n");
        $refreshtask->execute();
    }

    public function test_metadata_refresh_idpmetadata_notconfigured(): void {
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', null, 'auth_saml2');

        $refreshtask = new metadata_refresh();

        $this->expectOutputString('IdP metadata not configured.' . "\n");
        self::assertFalse($refreshtask->execute());
    }

    public function test_metadata_refresh_fetch_fails(): void {
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', 'http://somefakeidpurl.local', 'auth_saml2');

        $setting = $this->createMock(setting_idpmetadata::class);
        $setting->expects($this->once())
            ->method('validate')
            ->with('http://somefakeidpurl.local')
            ->willReturn('Metadata fetch failed.');

        $refreshtask = new metadata_refresh();
        $refreshtask->set_idpmetadata($setting);

        $this->expectOutputString("Metadata fetch failed.\n");
        self::assertFalse($refreshtask->execute());
    }

    public function test_metadata_refresh_parse_fails(): void {
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', 'http://somefakeidpurl.local', 'auth_saml2');

        $setting = $this->createMock(setting_idpmetadata::class);
        $setting->method('validate')->willReturn('Error parsing XML.');

        $refreshtask = new metadata_refresh();
        $refreshtask->set_idpmetadata($setting);

        $this->expectOutputString("Error parsing XML.\n");
        self::assertFalse($refreshtask->execute());
    }

    public function test_metadata_refresh_parse_no_entityid(): void {
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', 'http://somefakeidpurl.local', 'auth_saml2');

        $setting = $this->createMock(setting_idpmetadata::class);
        $setting->method('validate')->willReturn('Metadata does not contain an entity ID.');

        $refreshtask = new metadata_refresh();
        $refreshtask->set_idpmetadata($setting);

        $this->expectOutputString("Metadata does not contain an entity ID.\n");
        self::assertFalse($refreshtask->execute());
    }

    public function test_metadata_refresh_with_default_idp_name_succeeds(): void {
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', 'http://somefakeidpurl.local', 'auth_saml2');

        $setting = $this->createMock(setting_idpmetadata::class);
        $setting->method('validate')->willReturn(true);

        $refreshtask = new metadata_refresh();
        $refreshtask->set_idpmetadata($setting);

        $this->expectOutputString("IdP metadata refresh completed successfully.\n");
        self::assertTrue($refreshtask->execute());
    }

    public function test_metadata_refresh_write_fails(): void {
        set_config('idpmetadatarefresh', 1, 'auth_saml2');
        set_config('idpmetadata', 'http://somefakeidpurl.local', 'auth_saml2');

        $setting = $this->createMock(setting_idpmetadata::class);
        $setting->method('validate')->willReturn('Metadata write failed.');

        $refreshtask = new metadata_refresh();
        $refreshtask->set_idpmetadata($setting);

        $this->expectOutputString("Metadata write failed.\n");
        self::assertFalse($refreshtask->execute());
    }
}
