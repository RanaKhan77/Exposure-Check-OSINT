<?php

declare(strict_types=1);

namespace App\Modules\Osint;

use App\Modules\Osint\Sources\BlueskySource;
use App\Modules\Osint\Sources\CrtShSource;
use App\Modules\Osint\Sources\DisifySource;
use App\Modules\Osint\Sources\DisposableEmailSource;
use App\Modules\Osint\Sources\FachaTempSource;
use App\Modules\Osint\Sources\GitHubPublicSource;
use App\Modules\Osint\Sources\GravatarSource;
use App\Modules\Osint\Sources\HackerNewsSource;
use App\Modules\Osint\Sources\HudsonRockSource;
use App\Modules\Osint\Sources\IpapiIsSource;
use App\Modules\Osint\Sources\KickboxDisposableSource;
use App\Modules\Osint\Sources\MailcheckSource;
use App\Modules\Osint\Sources\MaigretSource;
use App\Modules\Osint\Sources\OsintSource;
use App\Modules\Osint\Sources\PhoneValiditySource;
use App\Modules\Osint\Sources\PresendSource;
use App\Modules\Osint\Sources\PwnedPasswordsSource;
use App\Modules\Osint\Sources\ProxyNovaCombSource;
use App\Modules\Osint\Sources\RdapSource;
use App\Modules\Osint\Sources\ShodanInternetDbSource;
use App\Modules\Osint\Sources\BotCidrSource;
use App\Modules\Osint\Sources\XposedOrNotSource;
use App\Services\SettingsService;
use Illuminate\Http\Client\Pool;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * Exposure Check orchestrator (Community Edition).
 *
 * Extracted from the 2MNY production engine (2026-10-21) with the CE deltas:
 *   - Check types: email | username | phone | password | domain | ip.
 *     The 'domain' type (added v1.3.0) surfaces a domain's public
 *     infrastructure footprint only — CT-log subdomain history and
 *     registry data. Website vulnerability scanning stays in the
 *     Website Vulnerability Scanner CE.
 *   - Keyless sources only (21). The owner-keyed source of the hosted
 *     product is NOT shipped here.
 *   - No Trace-Pro / billing logic anywhere in the CE.
 *
 * Fans out every supporting source in ONE Http::pool (single wall-clock
 * budget), merges results, computes an honest exposure score, and persists
 * an ExposureCheck audit row (identifier stored as salted hash + masked form).
 *
 * Scoring philosophy (matches the platform's honest-scanner rules):
 *   critical hit  = 40 pts (stealer exposure / exposed credentials)
 *   high hit      = 25 pts (CVEs, abuse flags)
 *   medium hit    = 12 pts
 *   low hit       = 5 pts
 *   info / clean  = 0 pts
 *   score = 100 - sum (clamped 0-100); more sources = more precise, never fake.
 *   Password checks are client-matched (k-anonymity) and DO NOT get a score.
 */
class OsintCheckService
{
    /** @var array<class-string<OsintSource>> */
    public const SOURCES = [
        HudsonRockSource::class,
        MaigretSource::class,
        XposedOrNotSource::class,
        ProxyNovaCombSource::class,
        PwnedPasswordsSource::class,
        MailcheckSource::class,
        GravatarSource::class,
        DisposableEmailSource::class,
        ShodanInternetDbSource::class,
        IpapiIsSource::class,
        PhoneValiditySource::class,
        // OSINT Phase 1 (2026-10-20): free keyless sources, live-verified
        DisifySource::class,
        KickboxDisposableSource::class,
        FachaTempSource::class,
        PresendSource::class,
        BlueskySource::class,
        HackerNewsSource::class,
        // v2.1 (2026-10-20): where-is-this-identifier-used signals (free)
        GitHubPublicSource::class,
        // v1.2.0 (2026-10-21, S32): offline bot-CIDR attribution (CrawlerScope-inspired)
        BotCidrSource::class,
        // v1.3.0 (2026-10-22, gap-analysis D1): domain-infra sources, keyless
        CrtShSource::class,
        RdapSource::class,
    ];

    public const TYPES = ['email', 'username', 'phone', 'password', 'domain', 'ip'];

    /** 30-min result cache per (type + normalized identifier). */
    private const CACHE_TTL = 1800;

    public function __construct(private readonly SettingsService $settings)
    {
    }

    /**
     * Sources for a run: the class list minus anything disabled on the
     * Settings page (key "sources.<key>.enabled" = false).
     *
     * @return array<int, OsintSource>
     */
    public function activeSources(string $type): array
    {
        $out = [];
        foreach (self::SOURCES as $cls) {
            $src = app($cls);
            if (!$src->supports($type)) {
                continue;
            }
            if (!$this->settings->get("sources.{$src->key()}.enabled", true)) {
                continue;
            }
            $out[] = $src;
        }

        return $out;
    }

    public function run(string $type, string $identifier): array
    {
        $type = strtolower(trim($type));
        if (!in_array($type, self::TYPES, true)) {
            throw new \InvalidArgumentException('Unsupported check type.');
        }

        $identifier = $this->normalize($type, $identifier);
        if ($identifier === '') {
            throw new \InvalidArgumentException('Invalid identifier for this check type.');
        }

        $cacheTtl = max(60, (int) $this->settings->get('cache_ttl_seconds', self::CACHE_TTL));
        $cacheKey = 'osint.check.v1:' . sha1($type . '|' . $identifier);
        $cached = Cache::get($cacheKey);
        if (is_array($cached)) {
            return $cached;
        }

        $sources = $this->activeSources($type);

        // ---- Phase 1: collect request specs --------------------------------
        $specs = [];
        foreach ($sources as $src) {
            foreach ($src->requests($type, $identifier) as $req) {
                $specs[] = $req + ['source' => $src->key()];
            }
        }

        // ---- Phase 2: single parallel pool ----------------------------------
        $responses = [];
        if ($specs !== []) {
            $ua = (string) $this->settings->get('user_agent', 'Exposure-Check-OSINT/1.0 (+https://github.com/RanaKhan77/Exposure-Check-OSINT)');
            $responses = Http::pool(function (Pool $pool) use ($specs, $ua) {
                $pending = [];
                foreach ($specs as $spec) {
                    $p = $pool->as($spec['name'])->timeout(9)->connectTimeout(6);
                    $headers = $spec['headers'] ?? [];
                    // Central honest UA (Settings page) unless the source
                    // deliberately sets its own.
                    if (!isset($headers['User-Agent']) && !isset($headers['user-agent'])) {
                        $headers['User-Agent'] = $ua;
                    }
                    if ($headers !== []) {
                        $p = $p->withHeaders($headers);
                    }
                    if (strtoupper($spec['method']) === 'POST') {
                        $pending[] = $p->post($spec['url'], $spec['body'] ?? []);
                    } else {
                        $pending[] = $p->get($spec['url']);
                    }
                }

                return $pending;
            });
        }

        // ---- Phase 3: parse per source --------------------------------------
        $results = [];
        $bySource = [];
        foreach ($sources as $src) {
            $mine = [];
            foreach ($src->requests($type, $identifier) as $req) {
                if (isset($responses[$req['name']])) {
                    $mine[$req['name']] = $responses[$req['name']];
                }
            }
            // Per-source parse isolation - a bug in ONE source must degrade
            // that card to honest-unavailable instead of throwing and killing
            // the whole check (production lesson, 2026-10-20).
            try {
                $bySource[$src->key()] = $src->parse($type, $identifier, $mine);
            } catch (\Throwable $e) {
                \Log::warning('osint source parse failed', [
                    'source' => $src->key(), 'type' => $type, 'error' => $e->getMessage(),
                ]);
                $bySource[$src->key()] = [
                    'status' => 'unavailable',
                    'summary' => 'This source could not process the response right now.',
                    'data' => [],
                ];
            }
        }

        // Deterministic, pleasing card order: stealer > breach > reputation >
        // profile > email > infra; alphabetical inside a group.
        $catOrder = ['stealer' => 0, 'breach' => 1, 'reputation' => 2, 'profile' => 3, 'email' => 4, 'infra' => 5];
        usort($sources, function (OsintSource $a, OsintSource $b) use ($catOrder) {
            $ca = $catOrder[$a->category()] ?? 9;
            $cb = $catOrder[$b->category()] ?? 9;

            return $ca === $cb ? strcmp($a->label(), $b->label()) : $ca - $cb;
        });

        foreach ($sources as $src) {
            $r = $bySource[$src->key()];
            $results[] = [
                'key' => $src->key(),
                'label' => $src->label(),
                'category' => $src->category(),
                'status' => $r['status'],
                'severity' => $r['severity'] ?? 'info',
                'summary' => $r['summary'],
                'data' => $r['data'],
            ];
        }

        // ---- Phase 4: summary + honest score --------------------------------
        $assessed = 0;
        $hits = 0;
        $points = 0;
        $weight = ['critical' => 40, 'high' => 25, 'medium' => 12, 'low' => 5, 'info' => 0];
        foreach ($results as $r) {
            if ($r['status'] === 'hit' || $r['status'] === 'clean') {
                $assessed++;
            }
            if ($r['status'] === 'hit') {
                $hits++;
                $points += $weight[$r['severity']] ?? 0;
            }
        }

        $score = null;
        $riskLabel = 'Not assessed';
        if ($type !== 'password' && $assessed > 0) {
            $score = max(0, 100 - $points);
            $riskLabel = $this->riskLabel($score, $hits);
        }

        $payload = [
            'type' => $type,
            'identifier_masked' => $this->mask($type, $identifier),
            'sources' => $results,
            'summary' => [
                'sources_supporting' => count($sources),
                'sources_assessed' => $assessed,
                'sources_unavailable' => count($sources) - $assessed,
                'hits' => $hits,
                'exposure_score' => $score,
                'risk_label' => $riskLabel,
            ],
        ];

        Cache::put($cacheKey, $payload, $cacheTtl);

        return $payload;
    }

    /**
     * Strip credential material from a result payload before it is
     * persisted to the exposure_checks audit row. Counts, masked emails
     * and every other field survive; only raw pairs are dropped.
     */
    public function sanitizeForStorage(array $result): array
    {
        if (!isset($result['sources']) || !is_array($result['sources'])) {
            return $result;
        }
        foreach ($result['sources'] as $i => $src) {
            if (is_array($src) && isset($src['data']) && is_array($src['data'])) {
                unset($result['sources'][$i]['data']['credential_lines']);
            }
        }

        return $result;
    }

    /**
     * HIBP breach-catalog STATS (keyless, cached 24h) for the dashboard chips.
     */
    public function catalogStats(): array
    {
        $cached = Cache::get('osint.hibp.catalogstats.v1');
        if (is_array($cached) && !empty($cached['breach_count'])) {
            return $cached;
        }

        $breaches = [];
        try {
            $resp = Http::timeout(15)
                ->withHeaders(['Accept' => 'application/json'])
                ->get('https://haveibeenpwned.com/api/v3/breaches');
            if ($resp->ok()) {
                $breaches = $resp->json() ?? [];
            }
        } catch (\Throwable $e) {
            $breaches = [];
        }

        if ($breaches === []) {
            // Never cache a failure — retry on the next request; callers fall
            // back to static floor numbers meanwhile.
            return ['breach_count' => 0, 'records_indexed' => 0, 'stealer_breaches' => 0, 'fetched_at' => null];
        }

        $records = 0;
        $stealer = 0;
        foreach ($breaches as $b) {
            $records += (int) ($b['PwnCount'] ?? 0);
            if (!empty($b['IsStealerLog'])) {
                $stealer++;
            }
        }

        $stats = [
            'breach_count' => count($breaches),
            'records_indexed' => $records,
            'stealer_breaches' => $stealer,
            'fetched_at' => now()->toDateTimeString(),
        ];
        Cache::put('osint.hibp.catalogstats.v1', $stats, 86400);

        return $stats;
    }

    public function landingStats(): array
    {
        $cat = $this->catalogStats();

        return [
            'breaches' => $cat['breach_count'] ?: 1045,
            'records' => $cat['records_indexed'] ?: 14000000000,
            'infections' => 36900000,
            'sources' => count(self::SOURCES),
        ];
    }

    /** Salted hash for storage/audit (identifier itself never stored raw). */
    public function identifierHash(string $type, string $identifier): string
    {
        return hash('sha256', config('app.key') . '|osint|' . $type . '|' . strtolower($identifier));
    }

    public function normalize(string $type, string $identifier): string
    {
        $identifier = trim($identifier);
        switch ($type) {
            case 'email':
                $identifier = strtolower($identifier);

                return filter_var($identifier, FILTER_VALIDATE_EMAIL) ? $identifier : '';
            case 'username':
                return preg_match('/^[A-Za-z0-9._-]{2,64}$/', $identifier) ? $identifier : '';
            case 'phone':
                // Keep digits only (E.164 without the leading plus).
                $digits = preg_replace('/\D+/', '', $identifier) ?? '';

                return (strlen($digits) >= 7 && strlen($digits) <= 15) ? $digits : '';
            case 'password':
                // 5-hex SHA-1 prefix ONLY (k-anonymity - never the password,
                // never the full hash). Contract: controller validates the
                // same 5-hex prefix the browser sends; PwnedPasswordsSource
                // queries the HIBP range with it and the browser matches the
                // full hash client-side. (Test-enforced: SourceContractTest.)
                return preg_match('/^[0-9A-Fa-f]{5}$/', $identifier) ? strtoupper($identifier) : '';
            case 'domain':
                // Public infrastructure identifier: strip scheme, path and
                // port, lowercase, and require a hostname shape (dot-joined
                // labels). FILTER_VALIDATE_DOMAIN alone accepts spaces and
                // underscores, so the shape check is the real gate.
                $identifier = strtolower((string) preg_replace('/^https?:\/\//', '', $identifier));
                $identifier = (string) preg_replace('/\/.*$/', '', $identifier);
                $identifier = (string) preg_replace('/:\d+$/', '', $identifier);

                return preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $identifier)
                    ? $identifier
                    : '';
            case 'ip':
                return filter_var($identifier, FILTER_VALIDATE_IP) ? $identifier : '';
        }

        return '';
    }

    public function mask(string $type, string $identifier): string
    {
        switch ($type) {
            case 'email':
                $at = strrpos($identifier, '@');
                if ($at === false) {
                    return '***';
                }
                $local = substr($identifier, 0, $at);
                $domain = substr($identifier, $at);

                return mb_substr($local, 0, 1) . '***' . ($local !== '' ? mb_substr($local, -1, 1) : '') . $domain;
            case 'username':
                return mb_substr($identifier, 0, 1) . '***' . ($identifier !== '' ? mb_substr($identifier, -1, 1) : '');
            case 'phone':
                return '+' . substr($identifier, 0, 3) . ' *** ***' . substr($identifier, -3);
            case 'password':
                return 'SHA-1 ' . substr($identifier, 0, 5) . '***** (k-anonymity)';
            case 'domain':
                // A domain is public infrastructure data, not a personal
                // identifier — shown as entered (matches the hosted product).
                return $identifier;
            case 'ip':
                // Privacy contract: never store a raw identifier. IPv4 keeps
                // first + last octet; IPv6 keeps first + last group; anything
                // unparseable is fully masked.
                if (filter_var($identifier, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $p = explode('.', $identifier);

                    return $p[0] . '.***.***.' . $p[3];
                }
                if (filter_var($identifier, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $g = explode(':', strtolower($identifier));

                    return ($g[0] ?? '') . ':***:***:' . end($g);
                }

                return '***.***.***.***';
            default:
                return '***';
        }
    }

    private function riskLabel(?int $score, int $hits): string
    {
        if ($score === null) {
            return 'Not assessed';
        }
        if ($hits === 0) {
            return 'No exposure found';
        }
        if ($score < 40) {
            return 'Critical exposure';
        }
        if ($score < 70) {
            return 'Elevated exposure';
        }
        if ($score < 95) {
            return 'Minor exposure';
        }

        return 'Low exposure';
    }
}
