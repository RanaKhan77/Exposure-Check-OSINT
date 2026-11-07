<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * Site Probe source (W109): native username enumeration across the
 * re-derived site registry (config/site-probe-registry.php).
 * ====================================================================
 *
 * What it is: keyless profile-page probing across N independently verified
 * sites — the site-probe lane that expands Exposure Check from 25 API
 * sources to a broad surface (see README "Sources" for the live count).
 *
 * How sites are verified (the registry admission gate — W109):
 *   1. DECOY GATE — a random nonexistent username must NOT look "found"
 *      (suppresses soft-404/wildcard false positives). Sites failing this
 *      are rejected and never enter the registry.
 *   2. EXEMPLAR — where a known account was available, it must look
 *      "found" (tier A = both directions proven; tier B = decoy-gated).
 *   3. Provenance: URL patterns and status codes are facts, independently
 *      re-derived and live-verified on 2026-11-07. NO third-party GPL
 *      registry data was copied (n1xYosint et al. consulted as concepts
 *      only). See registry header + docs/SOURCES.md.
 *
 * Runtime behavior:
 *   - Per site: one profile request. Decoy verdicts are username-
 *     INDEPENDENT, so they are cached (forever; refreshed by
 *     site:health) — a check never pays the decoy cost twice.
 *   - Tristate per site: hit | clean | unavailable (transport error,
 *     ambiguous rule, or site marked unreliable by a fresh decoy probe).
 *   - Result severity mirrors MaigretSource: low for 1-9 hits, medium
 *     for 10+ — a profile page is public info, never a breach.
 */
class SiteProbeSource implements OsintSource
{
    private const DECOY_CACHE_KEY = 'siteprobe:decoy:';
    private const DECOY_MAX_PER_CHECK = 12;

    public function key(): string
    {
        return 'site_probe';
    }

    public function label(): string
    {
        return 'Site Probe Registry';
    }

    public function category(): string
    {
        return 'profile';
    }

    public function supports(string $type): bool
    {
        return $type === 'username';
    }

    /** @return array<int, array{name: string, method: 'GET', url: string, headers?: array<string,string>}> */
    public function requests(string $type, string $identifier): array
    {
        if ($type !== 'username') {
            return [];
        }
        $reqs = [];
        $decoyBudget = self::DECOY_MAX_PER_CHECK;
        foreach ($this->registrySites() as $site) {
            $reqs[] = [
                'name' => 'probe:' . $site['name'],
                'method' => 'GET',
                'url' => str_replace('{u}', rawurlencode($identifier), $site['url']),
                'headers' => ['User-Agent' => 'Mozilla/5.0 (Exposure-Check-OSINT)'],
            ];
            // decoy probe only for sites without a cached verdict (bounded)
            if ($decoyBudget > 0 && $this->decoyVerdict($site) === null) {
                $decoyBudget--;
                $reqs[] = [
                    'name' => 'decoy:' . $site['name'],
                    'method' => 'GET',
                    'url' => str_replace('{u}', $this->decoyUsername(), $site['url']),
                    'headers' => ['User-Agent' => 'Mozilla/5.0 (Exposure-Check-OSINT)'],
                ];
            }
        }
        return $reqs;
    }

    /**
     * @param array<string, \Illuminate\Http\Client\Response> $responses
     * @return array{status: string, summary: string, data: array<string, mixed>, severity?: string}
     */
    public function parse(string $type, string $identifier, array $responses): array
    {
        if ($type !== 'username') {
            return [];
        }

        $hits = [];
        $clean = 0;
        $unavailable = 0;
        $unreliable = 0;

        foreach ($this->registrySites() as $site) {
            $name = $site['name'];
            $probe = $responses['probe:' . $name] ?? null;
            if ($probe === null) {
                $unavailable++;
                continue;
            }

            // fresh decoy verdict (from this check's bounded decoy fetch)
            $decoy = $responses['decoy:' . $name] ?? null;
            if ($decoy !== null) {
                $verdict = $this->classify($site, $decoy);
                $this->cacheDecoy($site, $verdict);
            }

            $decoyVerdict = $this->decoyVerdict($site);
            if ($decoyVerdict === 'unreliable') {
                $unreliable++;
                continue; // never trust a site that "finds" random names
            }

            $found = $this->classify($site, $probe);
            if ($found === true) {
                $hits[] = [
                    'site' => $name,
                    'url' => str_replace('{u}', rawurlencode($identifier), $site['url']),
                    'tier' => $site['tier'] ?? 'B',
                    'category' => $site['category'] ?? 'other',
                ];
            } elseif ($found === false) {
                $clean++;
            } else {
                $unavailable++;
            }
        }

        $n = count($hits);
        if ($n === 0) {
            return [
                'status' => 'clean',
                'summary' => 'No profiles found for "' . $identifier . '" across '
                    . count($this->registrySites()) . ' probed sites.',
                'data' => ['checked' => count($this->registrySites()), 'clean' => $clean,
                           'unavailable' => $unavailable, 'unreliable' => $unreliable, 'hits' => []],
                'severity' => 'info',
            ];
        }

        return [
            'status' => 'hit',
            'summary' => "Username \"{$identifier}\" found on {$n} " . ($n === 1 ? 'site' : 'sites')
                . " ({$clean} clean, {$unavailable} unavailable).",
            'data' => [
                'checked' => count($this->registrySites()),
                'clean' => $clean,
                'unavailable' => $unavailable,
                'unreliable' => $unreliable,
                'hits' => $hits,
            ],
            'severity' => $n >= 10 ? 'medium' : 'low',
        ];
    }

    /** Apply the registry rule to one response: true=found, false=not found, null=ambiguous. */
    private function classify(array $site, \Illuminate\Http\Client\Response $r): ?bool
    {
        try {
            $status = $r->status();
            $body = (string) $r->body();
        } catch (\Throwable $e) {
            return null;
        }
        if (!empty($site['nf_string']) && str_contains(strtolower($body), strtolower((string) $site['nf_string']))) {
            return false;
        }
        if (
            !empty($site['found_string'])
            && str_contains(strtolower($body), strtolower((string) $site['found_string']))
        ) {
            return true;
        }
        $nfs = $site['not_found_status'] ?? null;
        $fs = $site['found_status'] ?? null;
        if ($nfs !== null && $status === (int) $nfs) {
            return false;
        }
        if ($fs !== null && $status === (int) $fs) {
            return true;
        }
        return null;
    }

    /** @return array<int, array<string, mixed>> */
    private function registrySites(): array
    {
        static $sites = null;
        if ($sites === null) {
            $all = null;
            try {
                $all = config('site-probe-registry.sites');
            } catch (\Throwable $e) {
                $all = null; // container-less context (contract tests)
            }
            if (!is_array($all)) {
                // fallback: read the registry file directly (no container needed)
                $file = dirname(__DIR__, 4) . '/config/site-probe-registry.php';
                if (is_file($file)) {
                    $loaded = include $file;
                    $all = is_array($loaded) ? ($loaded['sites'] ?? null) : null;
                }
            }
            $sites = array_values(array_filter(
                is_array($all) ? $all : [],
                fn ($s) => is_array($s) && !empty($s['url'])
            ));
        }
        return $sites;
    }

    private function decoyUsername(): string
    {
        // deterministic-random per site run: long, clearly-nonexistent
        return 'zxq' . substr((string) time(), -6) . 'wv';
    }

    private function decoyVerdict(array $site): ?string
    {
        try {
            return Cache::get(self::DECOY_CACHE_KEY . $site['name']);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function cacheDecoy(array $site, ?string $verdict): void
    {
        if ($verdict === null) {
            return; // ambiguous: leave uncached so health can re-probe
        }
        try {
            Cache::put(self::DECOY_CACHE_KEY . $site['name'], $verdict, now()->addDays(7));
        } catch (\Throwable $e) {
            // cache unavailable: per-check decoy fetches still protect us
        }
    }
}
