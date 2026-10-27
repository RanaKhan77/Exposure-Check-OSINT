<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;

/**
 * mailcheck.ai - keyless email-domain intelligence.
 *
 * P4-S3 (2026-10-27) reliability fixes (was 29/29 "unavailable" on the admin
 * health panel):
 *  1. The bare host `mailcheck.ai/domain/...` now 301s to usercheck.com
 *     (Cloudflare JS challenge — unusable server-side). The keyless API host
 *     `api.mailcheck.ai/domain/...` still serves the same JSON schema.
 *  2. api.mailcheck.ai enforces a tight unauthenticated per-IP quota
 *     (observed: exhausted after ~5 requests/hour, Retry-After 3180s). Two
 *     guards make that survivable:
 *       - successful responses are cached per-domain for 24h (domain mail
 *         posture is slow-changing; popular domains amortize to ~1 call/day);
 *       - on API failure the last-good payload is served for up to 7 days
 *         with an honest "(cached …)" marker — the stale-data grace period.
 *     The card only degrades to unavailable when there has never been a
 *     good response for that domain.
 *
 * GET https://api.mailcheck.ai/domain/{domain} -> {domain_age_in_days, mx, mx_records,
 * mx_providers, spf, dmarc, disposable, public_domain, relay_domain,
 * free_subdomain, spam, did_you_mean}
 *
 * NOTE v2 schema: spf/dmarc are strings ("strict"/"relaxed"/"none") or null
 * rather than booleans. parse() normalizes both shapes.
 *
 * Used for both email checks (deliverability + disposable detection) and
 * domain checks (mail hardening posture at a glance).
 */
class MailcheckSource implements OsintSource
{
    private const URL = 'https://api.mailcheck.ai/domain/';

    /** Fresh-response cache per domain (upstream is slow-changing data). */
    private const FRESH_TTL = 86400; // 24 h

    /** Last-good stale-grace window when the API is rate-limited/down. */
    private const STALE_TTL = 604800; // 7 days

    public function key(): string
    {
        return 'mailcheck';
    }

    public function label(): string
    {
        return 'Mailcheck — Email Domain Intelligence';
    }

    public function category(): string
    {
        return 'email';
    }

    public function supports(string $type): bool
    {
        return in_array($type, ['email', 'domain'], true);
    }

    public function requests(string $type, string $identifier): array
    {
        $domain = $this->domainOf($type, $identifier);
        if ($domain === '' || !filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . urlencode($domain),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $domain = $this->domainOf($type, $identifier);
        $cacheKey = $domain !== '' ? 'osint.src.mailcheck.v1:' . $domain : '';

        $resp = $responses[$this->key() . '.main'] ?? null;
        if ($resp instanceof Response && $resp->ok()) {
            $j = $resp->json();
            if (is_array($j) && $j !== []) {
                // Remember the last-good payload (fresh for 24h, then it only
                // serves the stale grace window until a newer success lands).
                if ($cacheKey !== '') {
                    try {
                        Cache::put($cacheKey, ['j' => $j, 'at' => time()], self::STALE_TTL);
                    } catch (\Throwable $e) {
                        // cache backend hiccup must never break the card
                    }
                }

                return $this->verdict($j, false);
            }
        }

        // API failed (rate-limit 429 / timeout / 5xx): stale-data grace period.
        if ($cacheKey !== '') {
            $cached = Cache::get($cacheKey);
            if (is_array($cached) && is_array($cached['j'] ?? null)) {
                $ageH = isset($cached['at']) ? (int) round((time() - (int) $cached['at']) / 3600) : null;

                return $this->verdict($cached['j'], true, $ageH);
            }
        }

        return ['status' => 'unavailable', 'summary' => 'Email domain intelligence unavailable right now.', 'data' => []];
    }

    /**
     * Build the card verdict from a mailcheck payload. $stale marks data
     * served from the last-good cache because the API call failed.
     *
     * @param  array<string, mixed>  $j
     */
    private function verdict(array $j, bool $stale, ?int $ageHours = null): array
    {
        $disposable = (bool) ($j['disposable'] ?? false);
        $mx = (bool) ($j['mx'] ?? false);
        $spam = (bool) ($j['spam'] ?? false);
        $age = (int) ($j['domain_age_in_days'] ?? 0);
        $dym = (string) ($j['did_you_mean'] ?? '');

        // v2 schema (P4-S3): spf/dmarc can be bool (legacy), string
        // ("strict"/"relaxed"/"none") or null. A published, enforced policy is
        // any non-empty string other than "none" (or a literal true).
        $spfPolicy = $j['spf'] ?? null;
        $dmarcPolicy = $j['dmarc'] ?? null;
        $spf = is_bool($spfPolicy) ? $spfPolicy : (is_string($spfPolicy) && !in_array(strtolower($spfPolicy), ['none', ''], true));
        $dmarc = is_bool($dmarcPolicy) ? $dmarcPolicy : (is_string($dmarcPolicy) && !in_array(strtolower($dmarcPolicy), ['none', ''], true));

        $flags = [];
        if ($disposable) {
            $flags[] = 'disposable/temporary email provider';
        }
        if (!$mx) {
            $flags[] = 'no MX records (cannot receive mail)';
        }
        if ($spam) {
            $flags[] = 'flagged as spam-associated domain';
        }

        $data = [
            'disposable' => $disposable,
            'mx_present' => $mx,
            'spam_flagged' => $spam,
            'domain_age_days' => $age,
            'spf' => $spf,
            'dmarc' => $dmarc,
            'mx_providers' => is_array($j['mx_providers'] ?? null) ? array_slice($j['mx_providers'], 0, 4) : [],
        ];
        // v2: keep the raw policy strings for reports ("" when unpublished).
        $data['spf_policy'] = is_string($spfPolicy) ? $spfPolicy : ($spf ? 'published' : '');
        $data['dmarc_policy'] = is_string($dmarcPolicy) ? $dmarcPolicy : ($dmarc ? 'published' : '');
        if ($dym !== '') {
            $data['did_you_mean'] = $dym;
        }
        if ($stale) {
            $data['cached'] = true;
        }

        $staleNote = '';
        if ($stale) {
            $staleNote = ' (cached' . ($ageHours !== null && $ageHours >= 0 ? ' ' . $ageHours . 'h old' : '') . ' — live API rate-limited)';
        }

        if ($flags !== []) {
            return [
                'status' => 'hit',
                'summary' => 'Email domain concerns: ' . implode('; ', $flags) . '.' . $staleNote,
                'severity' => $disposable ? 'medium' : 'low',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'Email domain looks healthy'
                . ($age > 0 ? ' (domain age ' . number_format($age) . ' days)' : '')
                . ($spf && $dmarc ? ' with SPF+DMARC published' : '') . '.' . $staleNote,
            'severity' => 'info',
            'data' => $data,
        ];
    }

    private function domainOf(string $type, string $identifier): string
    {
        $domain = $type === 'email'
            ? strtolower(substr(strrchr($identifier, '@') ?: '', 1))
            : strtolower($identifier);

        return $domain === '' ? '' : $domain;
    }
}
