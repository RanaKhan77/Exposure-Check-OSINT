<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

/**
 * Bot-CIDR context (v1.2.0, S32 — CrawlerScope-inspired bot attribution).
 * ============================================================
 *
 * OFFLINE source: zero HTTP requests. Answers one question for IP checks:
 * "is this IP part of an operator-PUBLISHED crawler network range?"
 *
 * Why it matters (exposure-check context):
 *   - IN range: traffic from this IP is verifiable crawler traffic
 *     (Googlebot/Bingbot/Meta/Apple); verify via the documented PTR
 *     pattern before blocking or reporting it.
 *   - NOT in range: any user-agent CLAIMING to be those crawlers from
 *     this IP is spoofed — classic scanner-evasion / scraping signal.
 *
 * Honesty rules (same as the whole tool):
 *   - The table is a SNAPSHOT of operator-published prefixes (2026-10).
 *     A MISS is never proof of "not a crawler" — operators add ranges
 *     over time. The card says exactly that.
 *   - IPv6 inputs return a clean "not assessed (IPv4 ranges only)" —
 *     no silent wrong answers.
 */
class BotCidrSource implements OsintSource
{
    /**
     * Operator-published crawler prefixes (snapshot 2026-10).
     * format: prefix => [operator, kind, ptr_hint]
     */
    private const RANGES = [
        // Google — publishes the live list at
        // developers.google.com/search/apis/ipranges/googlebot.json
        '66.249.64.0/19'    => ['Google (Googlebot)', 'search_crawler', '*.googlebot.com / *.google.com'],
        '64.233.160.0/19'   => ['Google (Googlebot)', 'search_crawler', '*.googlebot.com / *.google.com'],
        '72.14.192.0/18'    => ['Google (Googlebot)', 'search_crawler', '*.googlebot.com / *.google.com'],
        '209.85.128.0/17'   => ['Google (Googlebot)', 'search_crawler', '*.googlebot.com / *.google.com'],
        '216.239.32.0/19'   => ['Google (Googlebot)', 'search_crawler', '*.googlebot.com / *.google.com'],
        '74.125.0.0/16'     => ['Google (Googlebot)', 'search_crawler', '*.googlebot.com / *.google.com'],
        // Microsoft — bing.com/toolbox/bingbot.json
        '157.55.39.0/24'    => ['Microsoft (Bingbot)', 'search_crawler', '*.search.msn.com'],
        '40.77.167.0/24'    => ['Microsoft (Bingbot)', 'search_crawler', '*.search.msn.com'],
        '207.46.12.0/23'    => ['Microsoft (Bingbot)', 'search_crawler', '*.search.msn.com'],
        // Meta — developers.facebook.com/docs/sharing/webmasters/crawler/
        '69.171.224.0/19'   => ['Meta (Facebook Crawler)', 'social_crawler', '*.facebook.com / *.tfbnw.net'],
        '66.220.144.0/20'   => ['Meta (Facebook Crawler)', 'social_crawler', '*.facebook.com / *.tfbnw.net'],
        '173.252.64.0/18'   => ['Meta (Facebook Crawler)', 'social_crawler', '*.facebook.com / *.tfbnw.net'],
        // Apple — developers.apple.com/applebot/
        '17.249.0.0/16'     => ['Apple (Applebot)', 'ai_crawler', '*.applebot.apple.com / *.apple.com'],
        '17.252.57.0/24'    => ['Apple (Applebot)', 'ai_crawler', '*.applebot.apple.com / *.apple.com'],
    ];

    public function key(): string
    {
        return 'botcidr';
    }

    public function label(): string
    {
        return 'Bot CIDR Attribution — Crawler Network Check';
    }

    public function category(): string
    {
        return 'infra';
    }

    public function supports(string $type): bool
    {
        return $type === 'ip';
    }

    /**
     * Offline source: no HTTP requests are ever issued.
     *
     * @return array<int, array<string, mixed>>
     */
    public function requests(string $type, string $identifier): array
    {
        return [];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $ip = trim($identifier);

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return [
                'status' => 'unavailable',
                'summary' => 'Bot-CIDR attribution applies to IPv4 addresses only.',
                'data' => ['note' => 'IPv6 crawler ranges are not covered by the offline snapshot.'],
                'severity' => 'info',
            ];
        }

        $hit = $this->lookup($ip);
        if ($hit !== null) {
            return [
                'status' => 'hit',
                'summary' => "Verified {$hit['operator']} crawler network range ({$hit['network']}).",
                'data' => [
                    'Operator' => $hit['operator'],
                    'Published range' => $hit['network'],
                    'Crawler kind' => $hit['kind'],
                    'Verify via reverse DNS' => $hit['ptr_hint'],
                    'What it means' => 'Traffic from this IP is crawler infrastructure. A website HOSTED here is unusual (likely a DNS misconfiguration). Requests FROM this range claiming the operator\'s user-agent are legitimate.',
                ],
                'severity' => 'info',
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'Not in any operator-published crawler range (Googlebot, Bingbot, Meta, Apple).',
            'data' => [
                'Checked against' => 'Googlebot, Bingbot, Meta crawler, Applebot published prefixes (offline snapshot 2026-10)',
                'What it means' => 'Any user-agent claiming to be those crawlers from this IP is SPOOFED — treat as automated scraping or scanning traffic.',
                'Note' => 'Operators add ranges over time; a miss is not absolute proof. Verify surprising traffic via the operator\'s documented reverse-DNS method.',
            ],
            'severity' => 'info',
        ];
    }

    /**
     * @return null|array{operator: string, network: string, kind: string, ptr_hint: string}
     */
    private function lookup(string $ip): ?array
    {
        $long = ip2long($ip);
        if ($long === false) {
            return null;
        }
        foreach (self::RANGES as $prefix => [$operator, $kind, $ptrHint]) {
            [$net, $bits] = explode('/', $prefix, 2);
            $netLong = ip2long($net);
            if ($netLong === false || !ctype_digit($bits) || (int) $bits < 0 || (int) $bits > 32) {
                continue;
            }
            $mask = (int) $bits === 0 ? 0 : ((-1 << (32 - (int) $bits)) & 0xFFFFFFFF);
            if (($long & $mask) === ($netLong & $mask)) {
                return [
                    'operator' => $operator,
                    'network' => $prefix,
                    'kind' => $kind,
                    'ptr_hint' => $ptrHint,
                ];
            }
        }
        return null;
    }
}
