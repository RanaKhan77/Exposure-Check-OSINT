<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * XposedOrNot free breach-analytics API (keyless) — 12th OSINT source.
 * Endpoint: https://api.xposedornot.com/v1/breach-analytics?email=<email>
 *
 * Payload on a HIT:
 *   BreachesSummary.site            "Breach1;Breach2;..." (semicolon list)
 *   ExposedBreaches.breaches_details[]{breach, xposed_date, xposed_records, ...}
 *   BreachMetrics.risk[]{risk_label, risk_score}
 *   BreachMetrics.passwords_strength[]{EasyToCrack, PlainText, StrongHash, Unknown}
 *   BreachMetrics.xposed_data[]     nested categories -> data-type -> count
 * Clean payload: {"BreachMetrics":null,"BreachesSummary":{"site":""},...}
 *
 * ETHICS (same rules as Hudson Rock card): aggregates only — breach names,
 * dates, record counts, risk classification and password-strength counts.
 * No plaintext passwords, no credential lines, no third-party identities
 * (this API returns none anyway).
 */
class XposedOrNotSource implements OsintSource
{
    private const BASE = 'https://api.xposedornot.com/v1/breach-analytics';

    public function key(): string
    {
        return 'xposedornot';
    }

    public function label(): string
    {
        return 'XposedOrNot — Breach Analytics';
    }

    public function category(): string
    {
        return 'breach';
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }

    public function requests(string $type, string $identifier): array
    {
        if ($type !== 'email') {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::BASE . '?email=' . urlencode($identifier),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Breach analytics unavailable right now.', 'data' => []];
        }

        $json = $resp->json();
        if (!is_array($json)) {
            return ['status' => 'unavailable', 'summary' => 'Breach analytics returned an unexpected response.', 'data' => []];
        }

        $details = [];
        if (is_array($json['ExposedBreaches'] ?? null)
            && is_array($json['ExposedBreaches']['breaches_details'] ?? null)) {
            $details = $json['ExposedBreaches']['breaches_details'];
        }
        $siteList = (string) ($json['BreachesSummary']['site'] ?? '');

        // Clean: null metrics + empty site list + no details
        if ($details === [] && trim($siteList) === '') {
            return [
                'status' => 'clean',
                'summary' => 'No breach records found for this email address.',
                'severity' => 'info',
                'data' => [
                    'breaches' => 0,
                    'note' => 'This email does not appear in the XposedOrNot breach corpus.',
                ],
            ];
        }

        // ---- aggregate breach facts ----
        $names = [];
        $dates = [];
        $records = 0;
        foreach ($details as $b) {
            if (!is_array($b)) {
                continue;
            }
            $n = (string) ($b['breach'] ?? '');
            if ($n !== '') {
                $names[] = $n;
            }
            $d = (string) ($b['xposed_date'] ?? '');
            if ($d !== '') {
                $dates[] = substr($d, 0, 10);
            }
            $r = (int) ($b['xposed_records'] ?? 0);
            if ($r > 0) {
                $records += $r;
            }
        }
        // Fallback when details list is empty but site list is not (defensive)
        if ($names === [] && $siteList !== '') {
            $names = array_values(array_filter(array_map('trim', explode(';', $siteList))));
        }
        $names = array_values(array_unique($names));
        sort($dates);

        // ---- risk classification ----
        $riskLabel = '';
        $riskScore = null;
        if (is_array($json['BreachMetrics'] ?? null)
            && is_array($json['BreachMetrics']['risk'] ?? null)) {
            foreach ($json['BreachMetrics']['risk'] as $r) {
                if (is_array($r)) {
                    $riskLabel = (string) ($r['risk_label'] ?? $riskLabel);
                    $riskScore = isset($r['risk_score']) ? (int) $r['risk_score'] : $riskScore;
                }
            }
        }

        // ---- password exposure counts (never plaintext) ----
        $pw = ['easy_to_crack' => 0, 'plaintext' => 0, 'strong_hash' => 0, 'unknown' => 0];
        if (is_array($json['BreachMetrics'] ?? null)
            && is_array($json['BreachMetrics']['passwords_strength'] ?? null)) {
            foreach ($json['BreachMetrics']['passwords_strength'] as $p) {
                if (is_array($p)) {
                    $pw['easy_to_crack'] += (int) ($p['EasyToCrack'] ?? 0);
                    $pw['plaintext']     += (int) ($p['PlainText'] ?? 0);
                    $pw['strong_hash']   += (int) ($p['StrongHash'] ?? 0);
                    $pw['unknown']       += (int) ($p['Unknown'] ?? 0);
                }
            }
        }

        // ---- top exposed data types ----
        $exposedTypes = [];
        if (is_array($json['BreachMetrics'] ?? null)
            && is_array($json['BreachMetrics']['xposed_data'] ?? null)) {
            $flat = [];
            $walk = function ($nodes) use (&$walk, &$flat) {
                foreach ($nodes as $node) {
                    if (!is_array($node)) {
                        continue;
                    }
                    $nm = (string) ($node['name'] ?? '');
                    $vl = (int) ($node['value'] ?? 0);
                    if ($nm !== '' && $vl > 0 && str_starts_with($nm, 'data_')) {
                        $flat[substr($nm, 5)] = $vl;
                    }
                    if (is_array($node['children'] ?? null)) {
                        $walk($node['children']);
                    }
                }
            };
            $walk($json['BreachMetrics']['xposed_data']);
            arsort($flat);
            $exposedTypes = array_slice($flat, 0, 5, true);
        }

        $count = max(count($names), count($details));
        $shown = array_slice($names, 0, 15);

        $data = [
            'breaches'         => $count,
            'breach_names'     => $shown,
            'more_names'       => max(0, count($names) - count($shown)),
            'first_breach'     => $dates[0] ?? null,
            'latest_breach'    => $dates !== [] ? $dates[count($dates) - 1] : null,
            'total_records'    => $records,
            'risk_label'       => $riskLabel ?: null,
            'risk_score'       => $riskScore,
            'passwords_exposed' => ($pw['easy_to_crack'] + $pw['plaintext'] + $pw['unknown'] + $pw['strong_hash']),
            'password_strength' => $pw,
            'top_exposed_data' => $exposedTypes,
        ];

        $severity = 'high';
        if ($riskScore !== null) {
            $severity = $riskScore >= 80 ? 'critical' : ($riskScore >= 50 ? 'high' : ($riskScore > 0 ? 'medium' : 'low'));
        } elseif ($count >= 10) {
            $severity = 'critical';
        }

        $summary = 'FOUND in ' . $count . ' data breach(es)'
            . ($riskLabel !== '' ? ' — risk: ' . $riskLabel . ' (' . $riskScore . '/100)' : '')
            . ($records > 0 ? ', ' . number_format($records) . ' total records exposed' : '') . '.';

        return [
            'status' => 'hit',
            'summary' => $summary,
            'severity' => $severity,
            'data' => $data,
        ];
    }
}
