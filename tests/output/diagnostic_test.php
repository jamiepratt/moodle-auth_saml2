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

namespace auth_saml2\output;

/**
 * Tests for the SAML diagnostic output.
 *
 * @package    auth_saml2
 * @copyright  2026 Shipmate
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[\PHPUnit\Framework\Attributes\CoversClass(diagnostic::class)]
final class diagnostic_test extends \basic_testcase {
    /**
     * External text is encoded while quotes and Unicode remain visible.
     */
    public function test_external_text_is_rendered_as_text(): void {
        $hostile = '<img src=x onerror="alert(1)"> O\'Hara & Zażółć 🛟';

        $html = diagnostic::paragraph('IdP: ', $hostile);

        $this->assertStringStartsWith('<p>', $html);
        $this->assertStringEndsWith('</p>', $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringContainsString(s($hostile), $html);
    }

    /**
     * Attribute JSON stays encoded within the structural pre element.
     */
    public function test_attribute_json_is_encoded_inside_pre(): void {
        $attributes = [
            '"><svg/onload=alert(1)>' => ['<script>alert("x")</script>', 'Zażółć 🛟'],
        ];

        $html = diagnostic::json($attributes);

        $this->assertStringStartsWith('<pre>', $html);
        $this->assertStringEndsWith('</pre>', $html);
        $this->assertStringNotContainsString('<svg', $html);
        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringContainsString('&lt;svg/onload=alert(1)&gt;', $html);
        $this->assertStringContainsString('Zażółć 🛟', $html);
    }
}
