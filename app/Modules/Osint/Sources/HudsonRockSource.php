<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Hudson Rock free OSINT API - stealer-log exposure (email / username / domain).
 * Keyless, corporate-grade metadata, 36.9M+ indexed infections.
 *
 * Response when infected: total_results, stealers[]{date_infected, malware_family,
 * computer_name, ip, url, ...}, corpos{...}. When clean: {"message": "..."}.
 *
 * ETHICS: we surface ONLY counts, infection dates and malware families.
 * Computer names, IPs, URLs and any third-party identifiers in the payload are
 * deliberately dropped - they belong to the (possibly shared) victim machine,
 * not to a public display card.
 */
class HudsonRockSource implements OsintSource
{
    private const BASE = 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-';

    public function key(): string
    {
        return 'hudsonrock';
    }

    public function label(): string
    {
        return 'Hudson Rock — Stealer Log Intelligence';
    }

    public function category(): string
    {
        return 'stealer';
    }

    public function supports(string $type): bool
    {
        return in_array($type, ['email', 'username', 'domain'], true);
    }

    public function requests(string $type, string $identifier): array
    {
        $variant = ['email' => 'email', 'username' => 'username', 'domain' => 'domain'][$type] ?? null;
        if ($variant === null) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::BASE . $variant . '?' . $variant . '=' . urlencode($identifier),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Stealer-log intelligence unavailable right now.', 'data' => []];
        }

        $json = $resp->json();
        if (!is_array($json)) {
            return ['status' => 'unavailable', 'summary' => 'Stealer-log intelligence returned an unexpected response.', 'data' => []];
        }

        $stealers = is_array($json['stealers'] ?? null) ? $json['stealers'] : [];
        $total = (int) ($json['total_results'] ?? count($stealers));

        if ($total <= 0 && $stealers === []) {
            return [
                'status' => 'clean',
                'summary' => 'No stealer-log infections found for this identifier.',
                'severity' => 'info',
                'data' => [
                    'infections' => 0,
                    'note' => 'This identifier does not appear in 36.9M+ indexed infostealer infections.',
                ],
            ];
        }

        // Aggregate only: dates + malware families (+ corporate signal as counts).
        $dates = [];
        $families = [];
        foreach ($stealers as $s) {
            if (!is_array($s)) {
                continue;
            }
            $d = (string) ($s['date_infected'] ?? '');
            if ($d !== '') {
                $dates[] = $d;
            }
            $f = (string) ($s['malware_family'] ?? '');
            if ($f !== '') {
                $families[] = $f;
            }
        }
        $families = array_values(array_unique($families));
        sort($dates);

        $corpoServices = 0;
        if (is_array($json['corpos'] ?? null)) {
            $corpoServices = count($json['corpos']);
        } elseif (is_int($json['corpos'] ?? null)) {
            $corpoServices = $json['corpos'];
        }

        $data = [
            'infections' => max($total, count($stealers)),
            'first_seen' => $dates[0] ?? null,
            'last_seen' => $dates !== [] ? $dates[count($dates) - 1] : null,
            'malware_families' => $families,
            'corporate_services_exposed' => $corpoServices,
        ];

        $summary = 'FOUND in ' . $data['infections'] . ' stealer-log infection(s)'
            . ($families !== [] ? ' (' . implode(', ', array_slice($families, 0, 3)) . ')' : '')
            . ' — saved credentials from this machine are at risk.';

        return [
            'status' => 'hit',
            'summary' => $summary,
            'severity' => 'critical',
            'data' => $data,
        ];
    }
}
