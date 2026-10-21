<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Shodan InternetDB - keyless, one-shot IP exposure summary.
 * GET https://internetdb.shodan.io/{ip} -> {cpes[], hostnames[], ip, ports[],
 * tags[], vulns[]} - open ports, hostnames, product CPEs and known CVEs.
 */
class ShodanInternetDbSource implements OsintSource
{
    private const URL = 'https://internetdb.shodan.io/';

    public function key(): string
    {
        return 'shodan';
    }

    public function label(): string
    {
        return 'Shodan InternetDB — Exposure Scan';
    }

    public function category(): string
    {
        return 'infra';
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
                'url' => self::URL . $identifier,
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Shodan InternetDB unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'Shodan InternetDB returned an unexpected response.', 'data' => []];
        }

        $ports = array_values(array_filter(array_map('intval', (array) ($j['ports'] ?? []))));
        $vulns = array_values(array_filter((array) ($j['vulns'] ?? [])));
        $hostnames = array_slice((array) ($j['hostnames'] ?? []), 0, 8);
        $tags = array_slice((array) ($j['tags'] ?? []), 0, 6);

        if ($ports === [] && $vulns === [] && $hostnames === []) {
            return [
                'status' => 'clean',
                'summary' => 'No open ports or services indexed for this IP.',
                'severity' => 'info',
                'data' => ['ports' => [], 'vulns' => [], 'hostnames' => [], 'tags' => $tags],
            ];
        }

        $summary = count($ports) . ' open port(s) indexed: ' . implode(', ', array_slice($ports, 0, 8));
        if (count($ports) > 8) {
            $summary .= ' +' . (count($ports) - 8) . ' more';
        }
        if ($vulns !== []) {
            $summary .= ' · ' . count($vulns) . ' known CVE(s)';
        }

        return [
            'status' => 'hit',
            'summary' => $summary . '.',
            'severity' => $vulns !== [] ? 'high' : 'medium',
            'data' => [
                'ports' => $ports,
                'vulns' => array_slice($vulns, 0, 12),
                'vulns_count' => count($vulns),
                'hostnames' => $hostnames,
                'tags' => $tags,
            ],
        ];
    }
}
