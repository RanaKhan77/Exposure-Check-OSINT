<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * VPNDetection - keyless VPN, Tor and privacy-relay detection + ASN + country.
 * GET https://api.vpndetection.io/{ip}, no key and no daily cap
 * (https://vpndetection.io/terms#no-key, https://vpndetection.io/privacy).
 * A hosting ASN (asn.type) is reported as datacenter, as ipapi.is does.
 */
class VpnDetectionSource implements OsintSource
{
    private const URL = 'https://api.vpndetection.io/';

    public function key(): string
    {
        return 'vpndetection';
    }

    public function label(): string
    {
        return 'VPNDetection - VPN, Tor and Relay Detection';
    }

    public function category(): string
    {
        return 'reputation';
    }

    public function supports(string $type): bool
    {
        return $type === 'ip';
    }

    public function requests(string $type, string $identifier): array
    {
        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . rawurlencode($identifier),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'VPN detection unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j) || !array_key_exists('is_vpn', $j)) {
            return ['status' => 'unavailable', 'summary' => 'VPN detection returned an unexpected response.', 'data' => []];
        }

        $asn = is_array($j['asn'] ?? null) ? $j['asn'] : [];
        $loc = is_array($j['location'] ?? null) ? $j['location'] : [];
        $data = [
            'company' => (string) ($asn['name'] ?? ''),
            'datacenter' => ($asn['type'] ?? '') === 'hosting',
            'vpn' => (bool) $j['is_vpn'],
            'tor' => (bool) ($j['is_tor'] ?? false),
            'relay' => (bool) ($j['is_relay'] ?? false),
            'country' => (string) ($loc['country'] ?? ''),
            'asn' => !empty($asn['asn']) ? 'AS' . (int) $asn['asn'] : '',
        ];

        $flags = array_keys(array_filter([
            'vpn' => $data['vpn'],
            'tor' => $data['tor'],
            'relay' => $data['relay'],
            'datacenter' => $data['datacenter'],
        ]));

        if ($flags !== []) {
            return [
                'status' => 'hit',
                'summary' => 'IP classified as: ' . implode(', ', $flags) . '.',
                // A relay or a hosting network alone is weaker evidence than a VPN or Tor exit
                'severity' => $data['vpn'] || $data['tor'] ? 'medium' : 'low',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'No VPN, Tor, relay or datacenter flags - appears to be a regular'
                . (!empty($j['is_bogon']) ? ' (bogon/reserved)' : '') . ' IP address.',
            'severity' => 'info',
            'data' => $data,
        ];
    }
}
