<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Certificate-transparency subdomain discovery (keyless), P4-S3 hardened.
 *
 * crt.sh (`GET https://crt.sh/?q=%.{domain}&output=json&limit=200`) is the
 * classic keyless CT source but is frequently slow (>9s pool budget) or
 * returns 502 under load — 1-in-4 domain checks degraded to "unavailable"
 * and the admin health panel showed the tool rose.
 *
 * P4-S3 (2026-10-27) dual-endpoint strategy: BOTH requests are fired in the
 * same parallel Http::pool (zero added latency) and parse() uses whichever
 * answered:
 *   crtsh.main — crt.sh JSON API (primary, unlimited but slow/flaky)
 *   crtsh.alt  — Cert Spotter public issuances API (fast 200ms, keyless,
 *                100 req/hour unauthenticated — fine at our volume, and the
 *                30-min per-identifier cache absorbs repeats)
 *
 * Output shape is unchanged (subdomains + subdomain_count), so the exposure
 * check UI and Trace reports keep working.
 */
class CrtShSource implements OsintSource
{
    private const CRTSH_URL = 'https://crt.sh/?q=';
    private const CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances';

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
        $domain = strtolower($identifier);

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::CRTSH_URL . urlencode('%.' . $domain) . '&output=json&limit=200',
                'headers' => [
                    'Accept' => 'application/json',
                    // crt.sh intermittently 502s generic bot UAs; identify honestly.
                    'User-Agent' => '2mny-trace/1.0 (+https://2mny.com)',
                ],
            ],
            [
                'name' => $this->key() . '.alt',
                'method' => 'GET',
                'url' => self::CERTSPOTTER_URL . '?domain=' . urlencode($domain) . '&include_subdomains=true&expand=dns_names',
                'headers' => [
                    'Accept' => 'application/json',
                    'User-Agent' => '2mny-trace/1.0 (+https://2mny.com)',
                ],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $identifier = strtolower($identifier);

        // ---- Primary: crt.sh JSON -------------------------------------------
        $main = $responses[$this->key() . '.main'] ?? null;
        if ($main instanceof Response && $main->ok()) {
            $j = $main->json();
            if (is_array($j) && $j !== []) {
                $names = $this->filterNames($this->namesFromCrtSh($j), $identifier);
                if ($names !== []) {
                    return $this->result($names, 'crt.sh');
                }
                // Empty-but-valid crt.sh response: a legitimately unlisted
                // domain — still check the alternate before calling it clean.
                $alt = $this->parseAlt($responses, $identifier);
                if ($alt !== null) {
                    return $alt;
                }

                return [
                    'status' => 'clean',
                    'summary' => 'No certificates found in Certificate Transparency logs for this domain.',
                    'severity' => 'info',
                    'data' => ['subdomains' => [], 'subdomain_count' => 0],
                ];
            }
        }

        // ---- Fallback: Cert Spotter issuances -------------------------------
        $alt = $this->parseAlt($responses, $identifier);
        if ($alt !== null) {
            return $alt;
        }

        return ['status' => 'unavailable', 'summary' => 'Certificate Transparency lookup timed out (crt.sh is slow at times).', 'data' => []];
    }

    /**
     * @param  array<int, mixed>  $rows
     * @return array<int, string>
     */
    private function namesFromCrtSh(array $rows): array
    {
        $names = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            $name = strtolower((string) ($row['name_value'] ?? ''));
            foreach (explode("\n", $name) as $n) {
                $n = trim($n, " *.\"\t");
                if ($n !== '') {
                    $names[$n] = true;
                }
            }
        }

        return array_keys($names);
    }

    /**
     * Parse the Cert Spotter alternate response; null when it is unusable
     * (missing, failed, rate-limited or unparseable) so the caller can fall
     * through to honest-unavailable.
     */
    private function parseAlt(array $responses, string $identifier): ?array
    {
        $alt = $responses[$this->key() . '.alt'] ?? null;
        if (!$alt instanceof Response || !$alt->ok()) {
            return null;
        }

        $j = $alt->json();
        if (!is_array($j)) {
            return null;
        }

        $names = [];
        foreach ($j as $row) {
            if (!is_array($row) || !is_array($row['dns_names'] ?? null)) {
                continue;
            }
            foreach ($row['dns_names'] as $n) {
                $n = strtolower(trim((string) $n, " *.\"\t"));
                if ($n !== '') {
                    $names[$n] = true;
                }
            }
        }

        $names = $this->filterNames(array_keys($names), $identifier);
        if ($names === []) {
            // Valid response, no in-domain names: honest clean.
            return [
                'status' => 'clean',
                'summary' => 'No certificates found in Certificate Transparency logs for this domain.',
                'severity' => 'info',
                'data' => ['subdomains' => [], 'subdomain_count' => 0],
            ];
        }

        return $this->result($names, 'Cert Spotter CT mirror');
    }

    /**
     * Keep only names that belong to the queried domain (both endpoints can
     * return sibling noise), deduplicated + sorted.
     *
     * @param  array<int, string>  $names
     * @return array<int, string>
     */
    private function filterNames(array $names, string $identifier): array
    {
        $out = [];
        foreach ($names as $n) {
            if ($n === $identifier || str_ends_with($n, '.' . $identifier)) {
                $out[$n] = true;
            }
        }
        $out = array_keys($out);
        sort($out);

        return $out;
    }

    /**
     * @param  array<int, string>  $names
     */
    private function result(array $names, string $via): array
    {
        return [
            'status' => 'hit',
            'summary' => count($names) . ' hostname(s) found in Certificate Transparency logs — this is the domain\'s public TLS footprint.',
            'severity' => 'low',
            'data' => [
                'subdomain_count' => count($names),
                'subdomains' => array_slice($names, 0, 40),
                'source' => $via,
            ],
        ];
    }
}
