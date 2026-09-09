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
 * IdP selection form.
 *
 * @package   auth_saml2
 * @author    Rossco Hellmans <rosscohellmans@catalyst-au.net>
 * @copyright Catalyst IT
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_saml2\form;

defined('MOODLE_INTERNAL') || die();

use moodleform;

require_once("$CFG->libdir/formslib.php");

/**
 * IdP selection form.
 *
 * @package    auth_saml2
 * @author     Rossco Hellmans <rosscohellmans@catalyst-au.net>
 * @copyright  Catalyst IT
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class selectidp_buttons extends moodleform {
    /**
     * Definition
     */
    public function definition() {
        $mform = $this->_form;

        $metadataentities = $this->_customdata['metadataentities'];
        $storedchoiceidp = $this->_customdata['storedchoiceidp'];
        $wants = $this->_customdata['wants'];

        $mform->addElement('hidden', 'wants', $wants);
        $mform->setType('wants', PARAM_URL);
        $mform->addElement('checkbox', 'rememberidp', '', get_string('rememberidp', 'auth_saml2'));

        // Accept the selector's flat list and metadata-source groups used by other callers.
        $idps = [];
        foreach ($metadataentities as $id => $entities) {
            if (is_array($entities)) {
                $idps += $entities;
            } else {
                $idps[$id] = $entities;
            }
        }
        if (isset($idps[$storedchoiceidp])) {
            $remembered = $idps[$storedchoiceidp];
            $mform->addElement('html', $this->get_idpbutton($storedchoiceidp, $remembered->name, $remembered->logo, true));
            $mform->addElement('html', \html_writer::empty_tag('hr'));
            unset($idps[$storedchoiceidp]);
        }
        foreach ($idps as $idpentityid => $idp) {
            $mform->addElement('html', $this->get_idpbutton($idpentityid, $idp->name, $idp->logo));
        }
    }

    /**
     * Get IPD Button.
     *
     * @param string $idpentityid
     * @param string $idpname
     * @param string $logourl
     * @param bool $rememberedidp
     *
     * @return string
     */
    private function get_idpbutton($idpentityid, $idpname, $logourl, $rememberedidp = false) {
        $url = \auth_saml2\output\idp_logo::url($logourl);
        $logo = $url === null ? '' : \html_writer::empty_tag('img', ['src' => $url, 'alt' => '']) . ' ';
        $button = \html_writer::tag('button', $logo . s($idpname), [
            'value' => $idpentityid,
            'class' => 'btn idpbtn' . ($rememberedidp ? ' rememberedidp' : ''),
            'type' => 'submit',
            'name' => 'idp',
        ]);
        return \html_writer::div($button, 'fitem fitem_actionbuttons fitem_fsubmit');
    }
}
