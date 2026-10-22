<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * RDAP (Registration Data Access Protocol) - the modern WHOIS (keyless).
 * GET https://rdap.org/domain/{domain} - registrar, registration/expiry dates,
 * status. Registration age is a strong fraud/trust signal.
 */
class RdapSource implements OsintSource
{
    private const URL = 'https://rdap.org/domain/';

    public function key(): string
    {
        return 'rdap';
    }

    public function label(): string
    {
        return 'RDAP — Domain Registration Records';
    }

    public function category(): string
    {
        return 'infra';
    }

    public function supports(string $type): bool
    {
        return $type === 'domain';
    }

    public function requests(string $type, string $identifier): array
    {
        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . strtolower($identifier),
                'headers' => ['Accept' => 'application/rdap+json, application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response) {
            return ['status' => 'unavailable', 'summary' => 'RDAP lookup unavailable right now.', 'data' => []];
        }
        if ($resp->status() === 404) {
            return [
                'status' => 'hit',
                'summary' => 'Domain has NO RDAP registration record — it appears unregistered or the TLD has no RDAP.',
                'severity' => 'medium',
                'data' => ['registered' => false],
            ];
        }
        if (!$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'RDAP lookup unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'RDAP returned an unexpected response.', 'data' => []];
        }

        $registrar = '';
        foreach ((array) ($j['entities'] ?? []) as $e) {
            $roles = (array) ($e['roles'] ?? []);
            if (in_array('registrar', $roles, true)) {
                $v = $e['vcardArray'][1] ?? [];
                foreach ((array) $v as $field) {
                    if (($field[0] ?? '') === 'fn') {
                        $registrar = (string) ($field[3] ?? '');
                    }
                }
            }
        }

        $events = [];
        foreach ((array) ($j['events'] ?? []) as $ev) {
            $events[(string) ($ev['eventAction'] ?? '')] = (string) ($ev['eventDate'] ?? '');
        }

        $created = $events['registration'] ?? '';
        $ageDays = 0;
        if ($created !== '') {
            try {
                $ageDays = (int) (now()->diffInDays(\Carbon\Carbon::parse($created)));
            } catch (\Throwable $e) {
                $ageDays = 0;
            }
        }

        $data = [
            'registered' => true,
            'registrar' => $registrar,
            'created' => $created ? substr($created, 0, 10) : '',
            'expires' => isset($events['expiration']) ? substr($events['expiration'], 0, 10) : '',
            'age_days' => $ageDays,
            'status' => array_slice((array) ($j['status'] ?? []), 0, 4),
        ];

        $summary = 'Domain registered' . ($created ? ' since ' . substr($created, 0, 10) : '')
            . ($registrar !== '' ? ' via ' . $registrar : '')
            . ($ageDays > 0 ? ' (' . number_format($ageDays) . ' days old)' : '') . '.';

        // A normally-aged registration is informational context, not an
        // exposure finding — only young/unregistered domains raise a flag.
        if ($ageDays > 0 && $ageDays < 60) {
            $summary .= ' Very young domain — common in phishing campaigns.';

            return ['status' => 'hit', 'summary' => $summary, 'severity' => 'medium', 'data' => $data];
        }

        return ['status' => 'clean', 'summary' => $summary, 'severity' => 'info', 'data' => $data];
    }
}
