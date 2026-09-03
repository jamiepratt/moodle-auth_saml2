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
 * Utility class for fetching IDP metadata.
 *
 * @package    auth_saml2
 * @author     Sam Chaffee
 * @copyright  Copyright (c) 2017 Blackboard Inc. (http://www.blackboard.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace auth_saml2;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../../../lib/filelib.php');

/**
 * Utility class for fetching IDP metadata.
 *
 * @package    auth_saml2
 * @copyright  Copyright (c) 2017 Blackboard Inc. (http://www.blackboard.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class metadata_fetcher {
    /** Maximum number of HTTPS redirects followed for one metadata request. */
    public const MAX_REDIRECTS = 5;

    /** Maximum accepted metadata response size (2 MiB). */
    public const MAX_METADATA_BYTES = 2 * 1024 * 1024;

    /**
     * @var array
     */
    private $curlinfo = [];

    /**
     * @var string
     */
    private $curlerror = '';

    /**
     * @var int
     */
    private $curlerrorno = 0;

    /**
     * Fetch metadata
     *
     * @param string $url
     * @param \curl $curl
     * @return bool
     * @throws \moodle_exception
     */
    public function fetch($url, $curl = null) {
        if (!$curl instanceof \curl) {
            $curl = new \curl();
        }
        $options = [
            'CURLOPT_SSL_VERIFYPEER' => true,
            'CURLOPT_SSL_VERIFYHOST' => 2,
            'CURLOPT_PROTOCOLS' => CURLPROTO_HTTPS,
            'CURLOPT_REDIR_PROTOCOLS' => CURLPROTO_HTTPS,
            'CURLOPT_CONNECTTIMEOUT' => 10,
            'CURLOPT_FOLLOWLOCATION' => 0,
            'CURLOPT_MAXREDIRS'      => 0,
            'CURLOPT_TIMEOUT'        => 30,
            'CURLOPT_MAXFILESIZE'    => self::MAX_METADATA_BYTES,
            'CURLOPT_ENCODING'       => '',
            'CURLOPT_RETURNTRANSFER' => false,
            'CURLOPT_NOBODY'         => false,
        ];
        $currenturl = $url;
        for ($redirects = 0; $redirects <= self::MAX_REDIRECTS; $redirects++) {
            $this->require_https($currenturl);
            $xml = '';
            $received = false;
            $toolarge = false;
            $options['CURLOPT_WRITEFUNCTION'] = static function (
                $handle,
                string $chunk
            ) use (
                &$xml,
                &$received,
                &$toolarge
            ): int {
                $received = true;
                $length = strlen($chunk);
                if ($toolarge || strlen($xml) + $length > self::MAX_METADATA_BYTES) {
                    $toolarge = true;
                    return 0;
                }
                $xml .= $chunk;
                return $length;
            };
            try {
                $result = $curl->get($currenturl, [], $options);
            } finally {
                $curl->removeopt(['CURLOPT_WRITEFUNCTION']);
                $curl->setopt(['CURLOPT_RETURNTRANSFER' => true]);
            }
            if (!$received && is_string($result)) {
                $xml = $result;
                $toolarge = strlen($xml) > self::MAX_METADATA_BYTES;
            }
            $this->curlinfo = $curl->get_info();
            $this->curlerrorno = $curl->get_errno();

            if ($toolarge) {
                throw new \moodle_exception('metadatafetchtoolarge', 'auth_saml2');
            }
            if (!empty($this->curlerrorno)) {
                if ($this->curlerrorno === CURLE_FILESIZE_EXCEEDED) {
                    throw new \moodle_exception('metadatafetchtoolarge', 'auth_saml2');
                }
                $this->curlerror = $xml;
                throw new \moodle_exception('metadatafetchfailed', 'auth_saml2', '', $xml);
            }
            if (!empty($this->curlinfo['url'])) {
                $this->require_https((string) $this->curlinfo['url']);
            }
            if (empty($this->curlinfo['http_code'])) {
                throw new \moodle_exception('metadatafetchfailedunknown', 'auth_saml2');
            }
            $status = (int) $this->curlinfo['http_code'];
            if (in_array($status, [301, 302, 303, 307, 308], true)) {
                if ($redirects === self::MAX_REDIRECTS) {
                    throw new \moodle_exception('metadatafetchfailedstatus', 'auth_saml2', '', $status);
                }
                $location = (string) ($this->curlinfo['redirect_url'] ?? '');
                if ($location === '') {
                    foreach ($curl->getResponse() as $name => $value) {
                        if (strcasecmp((string) $name, 'Location') === 0) {
                            $location = is_array($value) ? (string) end($value) : (string) $value;
                            break;
                        }
                    }
                }
                if ($location === '') {
                    throw new \moodle_exception('metadatafetchfailedunknown', 'auth_saml2');
                }
                $currenturl = $this->resolve_redirect_url($currenturl, $location);
                $this->require_https($currenturl);
                continue;
            }
            if ($status !== 200) {
                throw new \moodle_exception('metadatafetchfailedstatus', 'auth_saml2', '', $status);
            }
            return $xml;
        }
        throw new \moodle_exception('metadatafetchfailedunknown', 'auth_saml2');
    }

    /**
     * Require an HTTPS URL before opening a connection.
     *
     * @param string $url URL to validate.
     */
    private function require_https(string $url): void {
        if (strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https') {
            throw new \moodle_exception('idpmetadata_httpsrequired', 'auth_saml2');
        }
    }

    /**
     * Resolve an HTTP Location value against the current HTTPS URL.
     *
     * @param string $baseurl Current URL.
     * @param string $location Redirect Location value.
     * @return string Resolved URL.
     */
    private function resolve_redirect_url(string $baseurl, string $location): string {
        $location = trim($location);
        if (parse_url($location, PHP_URL_SCHEME) !== null) {
            return $location;
        }
        $base = parse_url($baseurl);
        if (!is_array($base) || empty($base['host'])) {
            throw new \moodle_exception('metadatafetchfailedunknown', 'auth_saml2');
        }
        if (str_starts_with($location, '//')) {
            return 'https:' . $location;
        }
        $host = str_contains((string) $base['host'], ':') ? '[' . $base['host'] . ']' : $base['host'];
        $authority = 'https://' . $host;
        if (isset($base['port'])) {
            $authority .= ':' . $base['port'];
        }
        if (str_starts_with($location, '?')) {
            return $authority . ($base['path'] ?? '/') . $location;
        }
        [$path, $suffix] = array_pad(preg_split('/(?=[?#])/', $location, 2), 2, '');
        if (!str_starts_with($path, '/')) {
            $basepath = $base['path'] ?? '/';
            $path = substr($basepath, 0, (int) strrpos($basepath, '/') + 1) . $path;
        }
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
            } else {
                $segments[] = $segment;
            }
        }
        return $authority . '/' . implode('/', $segments) . $suffix;
    }

    /**
     * Get curl info
     *
     * @return array
     */
    public function get_curlinfo() {
        return $this->curlinfo;
    }

    /**
     * Get curl error no
     *
     * @return int
     */
    public function get_curlerrorno() {
        return $this->curlerrorno;
    }

    /**
     * Get curl error
     *
     * @return string
     */
    public function get_curlerror() {
        return $this->curlerror;
    }
}
