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

namespace auth_saml2\admin;

use admin_setting_configtextarea;
use auth_saml2\idp_data;
use auth_saml2\idp_parser;
use auth_saml2\metadata_fetcher;
use auth_saml2\metadata_trust_manager;
use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once("{$CFG->libdir}/adminlib.php");

/**
 * Class admin_setting_configtext_idpmetadata
 *
 * @package     auth_saml2
 * @copyright   Matt Porritt <mattp@catalyst-au.net>
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class setting_idpmetadata extends admin_setting_configtextarea {
    /** @var callable|null Metadata downloader override. */
    private $downloader;

    /** @var callable|null Metadata writer override. */
    private $writer;

    /**
     * Constructor.
     *
     * @param callable|null $downloader Metadata downloader override for controlled environments.
     * @param callable|null $writer Metadata writer override for controlled environments.
     */
    public function __construct(?callable $downloader = null, ?callable $writer = null) {
        $this->downloader = $downloader;
        $this->writer = $writer;

        // All parameters are hardcoded because there can be only one instance:
        // When it validates, it saves extra configs, preventing this component from being reused as is.
        parent::__construct(
            'auth_saml2/idpmetadata',
            get_string('idpmetadata', 'auth_saml2'),
            get_string('idpmetadata_help', 'auth_saml2'),
            '',
            PARAM_RAW,
            80,
            5
        );
    }

    /**
     * Validate data before storage
     *
     * @param string $value
     * @return true|string Error message in case of error, true otherwise.
     * @throws \coding_exception
     */
    public function validate($value) {
        $value = trim($value);
        if (empty($value)) {
            return true;
        }

        try {
            $idps = $this->get_idps_data($value);
            $manager = new metadata_trust_manager();
            if ($manager->review($value, $idps) === metadata_trust_manager::PENDING) {
                throw new setting_idpmetadata_exception(get_string('idpmetadata_pendingapproval', 'auth_saml2'));
            }
            $this->activate_metadata($idps, static function () use ($manager, $idps): void {
                $manager->approve_initial($idps);
            });
        } catch (setting_idpmetadata_exception | \moodle_exception $exception) {
            return $exception->getMessage();
        }

        return true;
    }

    /**
     * Activate metadata after out-of-band confirmation by an authorised owner.
     *
     * @param int $userid Approver user ID.
     * @param string $authority Owner or emergency delegate.
     * @param bool $outofbandconfirmed Whether the proposal was confirmed through a trusted separate channel.
     */
    public function approve_pending(int $userid, string $authority, bool $outofbandconfirmed): void {
        global $USER;

        if (!$outofbandconfirmed) {
            throw new \moodle_exception('metadataapprovalconfirmationrequired', 'auth_saml2');
        }
        if ((int) $USER->id !== $userid) {
            throw new \invalid_parameter_exception('The SAML metadata approver must match the current user.');
        }
        require_capability('moodle/site:config', \context_system::instance());

        $manager = new metadata_trust_manager();
        $manager->validate_authority($authority);
        $pending = $manager->get_pending_data();
        $this->activate_metadata($pending['idps'], static function () use (
            $manager,
            $pending,
            $userid,
            $authority
        ): void {
            set_config('idpmetadata', $pending['configvalue'], 'auth_saml2');
            $manager->record_pending_approval($userid, $authority);
        });
        $manager->clear_pending();
    }

    /**
     * Atomically activate metadata across database records and live files.
     *
     * @param idp_data[] $idps
     * @param callable|null $withtransaction Additional database-backed trust changes.
     */
    private function activate_metadata(array $idps, ?callable $withtransaction = null): void {
        global $DB;

        $files = $this->snapshot_metadata_files();
        $transaction = $DB->start_delegated_transaction();
        try {
            $this->process_all_idps_metadata($idps);
            if ($withtransaction !== null) {
                $withtransaction();
            }
            $transaction->allow_commit();
        } catch (\Throwable $exception) {
            $this->restore_metadata_files($files);
            $transaction->rollback($exception);
        }
    }

    /**
     * Process all idps metadata.
     *
     * @param idp_data[] $idps
     */
    private function process_all_idps_metadata($idps) {
        global $DB;

        $currentidpsrs = $DB->get_records('auth_saml2_idps');
        $oldidps = [];
        foreach ($currentidpsrs as $idpentity) {
            if (!isset($oldidps[$idpentity->metadataurl])) {
                $oldidps[$idpentity->metadataurl] = [];
            }

            $oldidps[$idpentity->metadataurl][$idpentity->entityid] = $idpentity;
        }

        foreach ($idps as $idp) {
            $this->process_idp_metadata($idp, $oldidps);
        }

        // We remove any old IdPs that are left over.
        $this->remove_old_idps($oldidps);
    }

    /**
     * Process idp metadata.
     *
     * @param idp_data $idp
     * @param mixed $oldidps
     * @throws setting_idpmetadata_exception
     */
    private function process_idp_metadata(idp_data $idp, &$oldidps) {
        $xpath = $this->get_idp_xml_path($idp);
        $idpelements = $this->find_all_idp_sso_descriptors($xpath);

        if ($idpelements->length == 1) {
            $this->process_idp_xml($idp, $idpelements->item(0), $xpath, $oldidps, 1);
        } else if ($idpelements->length > 1) {
            foreach ($idpelements as $childidpelements) {
                $this->process_idp_xml($idp, $childidpelements, $xpath, $oldidps, 0);
            }
        } else {
            throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2'));
        }

        $this->save_idp_metadata_xml($idp->idpurl, $idp->get_rawxml());
    }

    /**
     * Process idp metadata.
     *
     * @param idp_data $idp
     * @param DOMElement $idpelements
     * @param DOMXPath $xpath
     * @param mixed $oldidps
     * @param int $activedefault
     */
    private function process_idp_xml(
        idp_data $idp,
        DOMElement $idpelements,
        DOMXPath $xpath,
        &$oldidps,
        $activedefault = 0
    ) {
        global $DB;
        $entityid = $idpelements->getAttribute('entityID');
        if ($entityid === '') {
            throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2'));
        }

        // Locate a displayname element provided by the IdP XML metadata.
        $names = $xpath->query('.//mdui:DisplayName', $idpelements);
        $idpname = null;
        if ($names && $names->length > 0) {
            $idpname = $names->item(0)->textContent;
        } else if (!empty($idp->idpname)) {
            $idpname = $idp->idpname;
        } else {
            $idpname = get_string('idpnamedefault', 'auth_saml2');
        }

        // Locate a logo element provided by the IdP XML metadata.
        $logos = $xpath->query('.//mdui:Logo', $idpelements);
        $logo = null;
        if ($logos && $logos->length > 0) {
            $logo = $logos->item(0)->textContent;
        }

        if (isset($oldidps[$idp->idpurl][$entityid])) {
            $oldidp = $oldidps[$idp->idpurl][$entityid];

            if (!empty($idpname) && $oldidp->defaultname !== $idpname) {
                $DB->set_field('auth_saml2_idps', 'defaultname', $idpname, ['id' => $oldidp->id]);
            }

            if (!empty($logo) && $oldidp->logo !== $logo) {
                $DB->set_field('auth_saml2_idps', 'logo', $logo, ['id' => $oldidp->id]);
            }

            // Remove the idp from the current array so that we don't delete it later.
            unset($oldidps[$idp->idpurl][$entityid]);
        } else {
            $newidp = new \stdClass();
            $newidp->metadataurl = $idp->idpurl;
            $newidp->entityid = $entityid;
            $newidp->activeidp = $activedefault;
            $newidp->defaultidp = 0;
            $newidp->adminidp = 0;
            $newidp->defaultname = $idpname;
            $newidp->logo = $logo;

            $DB->insert_record('auth_saml2_idps', $newidp);
        }
    }

    /**
     * Process idp metadata.
     *
     * @param mixed $oldidps
     */
    private function remove_old_idps($oldidps) {
        global $DB;

        foreach ($oldidps as $metadataidps) {
            foreach ($metadataidps as $oldidp) {
                $DB->delete_records('auth_saml2_idps', ['id' => $oldidp->id]);
            }
        }
    }

    /**
     * Get idps data.
     *
     * @param string $value
     * @return idp_data[]
     */
    public function get_idps_data($value) {
        global $CFG;

        require_once($CFG->libdir . '/filelib.php');

        $parser = new idp_parser();
        $idps = $parser->parse($value);

        // Download the XML if it was not parsed from the ipdmetadata field.
        foreach ($idps as $idp) {
            if (!is_null($idp->get_rawxml())) {
                continue;
            }

            if (strtolower((string) parse_url($idp->idpurl, PHP_URL_SCHEME)) !== 'https') {
                throw new setting_idpmetadata_exception(get_string('idpmetadata_httpsrequired', 'auth_saml2'));
            }

            $downloader = $this->downloader ?? static function (string $url): string {
                return (new metadata_fetcher())->fetch($url);
            };
            try {
                $rawxml = $downloader($idp->idpurl);
            } catch (\moodle_exception $exception) {
                throw new setting_idpmetadata_exception($exception->getMessage(), 0, $exception);
            }
            if ($rawxml === false) {
                throw new setting_idpmetadata_exception(
                    get_string('idpmetadata_badurl', 'auth_saml2', $idp->idpurl)
                );
            }
            $idp->set_rawxml($rawxml);
        }

        return $idps;
    }

    /**
     * Get idp xml path.
     *
     * @param idp_data $idp
     * @return DOMXPath
     */
    private function get_idp_xml_path(idp_data $idp) {
        $xml = new DOMDocument();

        libxml_use_internal_errors(true);

        $rawxml = $idp->rawxml;

        if (!$xml->loadXML($rawxml, LIBXML_PARSEHUGE | LIBXML_NONET)) {
            $errors = libxml_get_errors();
            $lines = explode("\n", $rawxml);
            $msg = '';
            foreach ($errors as $error) {
                $msg .= "<br>Error ({$error->code}) line $error->line char  $error->column: $error->message";
            }

            throw new setting_idpmetadata_exception(get_string('idpmetadata_invalid', 'auth_saml2') . $msg);
        }

        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xpath->registerNamespace('mdui', 'urn:oasis:names:tc:SAML:metadata:ui');

        return $xpath;
    }

    /**
     * Find all idp SSO descriptors.
     *
     * @param DOMXPath $xpath
     * @return DOMNodeList
     */
    private function find_all_idp_sso_descriptors(DOMXPath $xpath) {
        $idpelements = $xpath->query('//md:EntityDescriptor[//md:IDPSSODescriptor]');
        return $idpelements;
    }

    /**
     * Save idp metadata xml.
     *
     * @param string $url
     * @param string $xml
     */
    private function save_idp_metadata_xml($url, $xml) {
        global $CFG, $saml2auth;
        require_once("{$CFG->dirroot}/auth/saml2/setup.php");

        $file = $saml2auth->get_file_idp_metadata_file($url);
        if ($this->writer !== null) {
            ($this->writer)($file, $xml);
            return;
        }

        $temporary = tempnam(dirname($file), '.metadata-');
        if (
            $temporary === false ||
            file_put_contents($temporary, $xml, LOCK_EX) === false ||
            !chmod($temporary, $CFG->filepermissions) ||
            !rename($temporary, $file)
        ) {
            if (is_string($temporary) && file_exists($temporary)) {
                unlink($temporary);
            }
            throw new setting_idpmetadata_exception(get_string('idpmetadata_writefailed', 'auth_saml2'));
        }
    }

    /**
     * Snapshot all live IdP metadata files.
     *
     * @return array
     */
    private function snapshot_metadata_files(): array {
        global $CFG;

        $files = [];
        foreach (glob($CFG->dataroot . '/saml2/*.idp.xml') ?: [] as $file) {
            $files[$file] = file_get_contents($file);
        }
        return $files;
    }

    /**
     * Restore all live IdP metadata files after an activation failure.
     *
     * @param array $snapshot File contents indexed by absolute path.
     */
    private function restore_metadata_files(array $snapshot): void {
        global $CFG;

        foreach (glob($CFG->dataroot . '/saml2/*.idp.xml') ?: [] as $file) {
            if (!array_key_exists($file, $snapshot)) {
                unlink($file);
            }
        }
        foreach ($snapshot as $file => $content) {
            file_put_contents($file, $content, LOCK_EX);
            chmod($file, $CFG->filepermissions);
        }
    }
}
