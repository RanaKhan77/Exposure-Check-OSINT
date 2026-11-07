<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Modules\Osint\Sources\SiteProbeSource;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * site:health — registry self-test (the n1xYosint site_health concept,
 * adopted natively in W109).
 * ====================================================================
 * For every site in config/site-probe-registry.php:
 *   1. probe a fresh random decoy username — a "found" result marks the
 *      site UNRELIABLE (cached for 7 days; the check source skips
 *      unreliable sites entirely);
 *   2. probe the exemplar account where configured — verifies the
 *      positive direction still works (drift detection: redesigns,
 *      login walls, API changes).
 *
 * Run weekly via scheduler or ad-hoc. Exit code 1 when any tier-A site
 * went unreliable or lost its exemplar (CI-friendly).
 */
class SiteHealthCommand extends Command
{
    protected $signature = 'site:health {--site= : probe a single registry site by name}';

    protected $description = 'Site-probe registry health self-test (decoy + exemplar)';

    private const UA = 'Mozilla/5.0 (Exposure-Check-OSINT site-health)';

    public function handle(): int
    {
        $sites = config('site-probe-registry.sites', []);
        if (!is_array($sites) || $sites === []) {
            $this->error('site-probe registry is empty — config/site-probe-registry.php missing?');
            return 1;
        }
        $only = (string) $this->option('site');
        $decoy = 'zxq' . substr((string) time(), -6) . 'wvhealth';

        $failures = 0;
        $rows = [];
        foreach ($sites as $site) {
            if ($only !== '' && ($site['name'] ?? '') !== $only) {
                continue;
            }
            $name = (string) ($site['name'] ?? '?');
            $url = (string) ($site['url'] ?? '');
            if ($url === '') {
                continue;
            }

            // 1. decoy probe
            [$ds, $db] = $this->fetch(str_replace('{u}', $decoy, $url));
            $decoyFound = $this->classify($site, $ds, $db);
            if ($decoyFound === true) {
                Cache::put('siteprobe:decoy:' . $name, 'unreliable', now()->addDays(7));
                $failures += ($site['tier'] ?? 'B') === 'A' ? 1 : 0;
                $rows[] = [$name, 'UNRELIABLE', "decoy matched ({$ds})", '-'];
                continue;
            }

            // 2. exemplar probe (positive direction)
            $exemplar = $site['exemplar'] ?? null;
            $exOk = null;
            if (is_string($exemplar) && $exemplar !== '') {
                [$es, $eb] = $this->fetch(str_replace('{u}', $exemplar, $url));
                $exOk = $this->classify($site, $es, $eb);
                if ($exOk !== true && ($site['tier'] ?? 'B') === 'A') {
                    $failures++;
                }
            }

            // cache the clean verdict so checks skip the decoy fetch
            if ($decoyFound === false) {
                Cache::put('siteprobe:decoy:' . $name, 'clean', now()->addDays(7));
            }
            $rows[] = [
                $name,
                $decoyFound === false ? 'ok' : 'ambiguous',
                "decoy={$ds}",
                $exemplar === null ? '-' : ($exOk === true ? 'ok' : ($exOk === false ? 'MISS' : '?')),
            ];
        }

        $this->table(['site', 'decoy', 'status', 'exemplar'], $rows);
        $this->info(sprintf('sites: %d | failures (tier A): %d', count($rows), $failures));
        return $failures > 0 ? 1 : 0;
    }

    /** @return array{0: ?int, 1: string} */
    private function fetch(string $url): array
    {
        try {
            $r = Http::timeout(10)
                ->withHeaders(['User-Agent' => self::UA, 'Accept-Language' => 'en-US,en;q=0.9'])
                ->withoutVerifying()
                ->get($url);
            return [$r->status(), (string) $r->body()];
        } catch (\Throwable $e) {
            return [null, ''];
        }
    }

    private function classify(array $site, ?int $status, string $body): ?bool
    {
        if ($status === null) {
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
}
