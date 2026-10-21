<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * ipapi.is - keyless IP classification (datacenter/VPN/Tor/proxy detection
 * + ASN + country). GET https://api.ipapi.is/?q={ip}
 */
class IpapiIsSource implements OsintSource
{
    private const URL = 'https://api.ipapi.is/?q=';

    public function key(): string
    {
        return 'ipapi';
    }

    public function label(): string
    {
        return 'ipapi.is — IP Classification';
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
                'url' => self::URL . urlencode($identifier),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'IP classification unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j) || !is_array($j['ip'] ?? null)) {
            return ['status' => 'unavailable', 'summary' => 'IP classification returned an unexpected response.', 'data' => []];
        }

        $ip = $j['ip'];
        $risk = (int) ($j['risk_score'] ?? 0);
        $flags = [];
        foreach (['is_datacenter', 'is_vpn', 'is_tor', 'is_proxy', 'is_abuser', 'is_crawler', 'is_bogon'] as $f) {
            if (!empty($ip[$f])) {
                $flags[] = str_replace('is_', '', $f);
            }
        }

        $asn = is_array($ip['asn'] ?? null) ? $ip['asn'] : [];
        $data = [
            'company' => (string) ($ip['company'] ?? ''),
            'datacenter' => (bool) ($ip['is_datacenter'] ?? false),
            'vpn' => (bool) ($ip['is_vpn'] ?? false),
            'tor' => (bool) ($ip['is_tor'] ?? false),
            'proxy' => (bool) ($ip['is_proxy'] ?? false),
            'abuser' => (bool) ($ip['is_abuser'] ?? false),
            'risk_score' => $risk,
            'country' => (string) ($ip['country'] ?? ''),
            'asn' => is_array($asn) ? (string) ($asn['org'] ?? '') : '',
        ];

        if ($flags !== []) {
            return [
                'status' => 'hit',
                'summary' => 'IP classified as: ' . implode(', ', $flags)
                    . ($risk > 0 ? ' (abuse risk score ' . $risk . '/100)' : '') . '.',
                'severity' => ($ip['is_abuser'] ?? false) || $risk >= 50 ? 'high' : 'medium',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'No VPN/proxy/datacenter flags — appears to be a regular'
                . ($ip['is_bogon'] ?? false ? ' (bogon/reserved)' : '') . ' IP address.',
            'severity' => 'info',
            'data' => $data,
        ];
    }
}
