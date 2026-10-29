<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

/**
 * DNS Blocklists (DNSBL) — Spamhaus ZEN + SpamCop + Barracuda (v1.6.0, W58).
 * ============================================================
 *
 * DNS-ONLY source: zero HTTP requests. For an IPv4 address, asks the three
 * largest public DNS blocklists "is this IP listed for spam/abuse?" by
 * resolving {reversed-ip}.{zone} — the classic DNSBL protocol. This answers
 * a personal-exposure question the other IP sources cannot: "is MY IP
 * flagged as a spam source?" (a listed home IP can mean a compromised
 * device, a hijacked router, or prior abuse from that address).
 *
 * Found in the W58 OSINT adoption research (cross-validated by two
 * independent model reviews): the CE already had ports (Shodan InternetDB),
 * classification (ipapi.is) and crawler ranges (BotCidr) — reputation
 * listings were the one keyless, personal, cheap signal missing.
 *
 * HONESTY RULES (the part most tools get wrong — live-verified on prod):
 *  - DNSBL refusal is AMBIGUOUS: Spamhaus refuses open/public-resolver
 *    queries sometimes with 127.255.255.x ERROR A-records, and sometimes
 *    with EMPTY answers (a known-listed test address silently returns
 *    "no A"). Both mean "no real answer" — NEVER "not listed".
 *  - Therefore each zone is first probed with the permanently-listed test
 *    address 127.0.0.2. Only if that probe demonstrably returns a listing
 *    do we trust the zone's answer for the checked IP. Otherwise the zone
 *    degrades to "not assessed" — a fake clean is impossible by design.
 *  - DNS/zone failures, restricted resolvers and IPv6 all degrade to
 *    "not assessed" / "unavailable" — never clean.
 *  - A listing is a signal, not a conviction: the card states the zone's
 *    classification and what it means.
 *
 * Return-code semantics (mapped; unknown codes still count as listed, raw
 * code shown):
 *  - Spamhaus ZEN: 127.0.0.2/3 SBL (spam), 127.0.0.4-7 XBL (exploit/proxy),
 *    127.0.0.6 PBL (policy/no-mail), 127.0.0.10/11 PBL (policy).
 *    Errors: 127.255.255.252 public resolver, .254 open resolver, .255 bad query.
 *  - SpamCop: any 127.0.0.x (except errors) = listed, spam-report-driven.
 *  - Barracuda: 127.0.0.2 = listed (poor reputation).
 */
class DnsblSource implements OsintSource
{
    /** Permanently listed test address (DNSBL convention) — our zone-health probe. */
    private const TEST_IP = '127.0.0.2';

    /** zone => [label, explanation] */
    private const ZONES = [
        'zen.spamhaus.org' => [
            'Spamhaus ZEN',
            'Listed on the combined Spamhaus SBL+XBL+PBL blocklist (spam, exploits or policy).',
        ],
        'bl.spamcop.net' => [
            'SpamCop',
            'Listed on the SpamCop blocklist (recent spam reports traced to this IP).',
        ],
        'b.barracudacentral.org' => [
            'Barracuda',
            'Listed on the Barracuda Reputation Blocklist (poor email reputation).',
        ],
    ];

    /** Spamhaus-style ERROR returns (query refused, never "not listed"). */
    private const ERROR_CODES = ['127.255.255.252', '127.255.255.254', '127.255.255.255'];

    public function key(): string
    {
        return 'dnsbl';
    }

    public function label(): string
    {
        return 'DNS Blocklists — Spamhaus ZEN, SpamCop, Barracuda';
    }

    public function category(): string
    {
        return 'reputation';
    }

    public function supports(string $type): bool
    {
        return $type === 'ip';
    }

    /**
     * DNS-only source: no HTTP requests are ever issued (same pattern as
     * BotCidrSource). The DNS queries happen inside parse().
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
                'summary' => 'DNS blocklists are queried for IPv4 addresses only.',
                'data' => ['note' => 'IPv6 blocklist semantics differ per zone and are not assessed.'],
                'severity' => 'info',
            ];
        }

        $listings = [];
        $notAssessed = [];
        $assessed = 0;

        foreach (self::ZONES as $zone => [$label, $explanation]) {
            // 1. HEALTH PROBE: the permanently-listed test address must
            //    demonstrably return a listing from this network — otherwise
            //    the zone is refusing us and any "no A" would be a fake clean.
            $probeCodes = $this->query(self::TEST_IP, $zone);
            $probeListed = $this->stripErrors($probeCodes);
            if ($probeListed === []) {
                $reason = $probeCodes !== []
                    ? 'query refused — public/open resolver'
                    : 'zone not answering from this network (could not verify via the listed test address)';
                $notAssessed[] = $label . ' (' . $reason . ')';
                continue;
            }

            // 2. REAL QUERY: the zone verifiably answers — now "no A" means
            //    genuinely not listed.
            $assessed++;
            $codes = $this->query($ip, $zone);
            $realCodes = $this->stripErrors($codes);
            if ($realCodes !== []) {
                $listings[] = [
                    'zone' => $label,
                    'explanation' => $explanation,
                    'codes' => $realCodes,
                ];
            }
        }

        if ($listings !== []) {
            $names = implode(', ', array_column($listings, 'zone'));
            $details = [];
            foreach ($listings as $l) {
                $details[$l['zone']] = $l['explanation'] . ' (return code: ' . implode(', ', $l['codes']) . ')';
            }

            return [
                'status' => 'hit',
                'summary' => 'This IP is LISTED on: ' . $names . '.',
                'data' => [
                    'Listed on' => $details,
                    'What it means' => 'A blocklist listing means mail and traffic from this IP is treated as spam or abuse by a large share of the internet. On a personal IP this often indicates a compromised device, a hijacked router, or abuse by a previous holder of the address.',
                    'Zones not assessed' => $notAssessed !== [] ? implode('; ', $notAssessed) : 'none',
                ],
                'severity' => 'medium',
            ];
        }

        if ($assessed > 0) {
            return [
                'status' => 'clean',
                'summary' => 'Not listed on ' . $assessed . ' of the queried DNS blocklists.',
                'data' => [
                    'Checked against' => 'Spamhaus ZEN, SpamCop, Barracuda (live DNS queries, each zone verified answering via its listed test address)',
                    'What it means' => 'No spam or abuse listing found for this IP on the zones that verifiably answered.',
                    'Zones not assessed' => $notAssessed !== [] ? implode('; ', $notAssessed) : 'none',
                ],
                'severity' => 'info',
            ];
        }

        return [
            'status' => 'unavailable',
            'summary' => 'DNS blocklists could not be queried from this network.',
            'data' => ['note' => implode('; ', $notAssessed)],
            'severity' => 'info',
        ];
    }

    /**
     * A-records for {reversed-ip}.{zone}; [] when none / on failure (the
     * health probe distinguishes "no answer" from "not listed").
     *
     * @return list<string>
     */
    private function query(string $ip, string $zone): array
    {
        $host = $this->reverseIp($ip) . '.' . $zone;
        $records = @dns_get_record($host, DNS_A);
        if (!is_array($records)) {
            return [];
        }
        $codes = [];
        foreach ($records as $r) {
            if (isset($r['ip']) && is_string($r['ip'])) {
                $codes[] = $r['ip'];
            }
        }

        return $codes;
    }

    /** @param list<string> $codes @return list<string> */
    private function stripErrors(array $codes): array
    {
        return array_values(array_diff($codes, self::ERROR_CODES));
    }

    /** 1.2.3.4 -> 4.3.2.1 (DNSBL query format). */
    private function reverseIp(string $ip): string
    {
        return implode('.', array_reverse(explode('.', $ip)));
    }
}
