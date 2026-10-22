<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * crt.sh certificate-transparency subdomain discovery (keyless).
 * GET https://crt.sh/?q=%.{domain}&output=json&limit=200 — every subdomain
 * that ever obtained a TLS certificate. Counts + names of the first 40.
 * crt.sh can be slow; 8s timeout, graceful unavailable on failure.
 */
class CrtShSource implements OsintSource
{
    private const URL = 'https://crt.sh/?q=';

    public function key(): string
    {
        return 'crtsh';
    }

    public function label(): string
    {
        return 'crt.sh — Certificate Transparency';
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
                'url' => self::URL . urlencode('%.' . strtolower($identifier)) . '&output=json&limit=200',
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Certificate Transparency lookup timed out (crt.sh is slow at times).', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'Certificate Transparency returned an unexpected response.', 'data' => []];
        }

        $names = [];
        foreach ($j as $row) {
            $name = strtolower((string) ($row['name_value'] ?? ''));
            foreach (explode("\n", $name) as $n) {
                $n = trim($n, " *.\"\t");
                if ($n !== '' && str_contains($n, $identifier)) {
                    $names[$n] = true;
                }
            }
        }
        $names = array_keys($names);
        sort($names);

        if ($names === []) {
            return [
                'status' => 'clean',
                'summary' => 'No certificates found in Certificate Transparency logs for this domain.',
                'severity' => 'info',
                'data' => ['subdomains' => [], 'subdomain_count' => 0],
            ];
        }

        return [
            'status' => 'hit',
            'summary' => count($names) . ' hostname(s) found in Certificate Transparency logs — this is the domain\'s public TLS footprint.',
            'severity' => 'low',
            'data' => [
                'subdomain_count' => count($names),
                'subdomains' => array_slice($names, 0, 40),
            ],
        ];
    }
}
