<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * LeakLens public breach-registry search (keyless MCP endpoint) — 22nd OSINT source.
 * Endpoint: https://leaklens.org/api/mcp (JSON-RPC 2.0, stateless tools/call)
 *
 * Scope (deliberate):
 *   - phone    -> tools/call search_phone   (NEW capability: phone breach exposure;
 *                 PhoneValiditySource only checks E.164 validity, not breaches)
 *   - username -> tools/call search_username (breach-flavored complement to the
 *                 Maigret platform-presence grid)
 *   - email    -> NOT here: XposedOrNotSource already queries the same upstream
 *                 corpus directly (LeakLens aggregates XposedOrNot, own:0/agg:795)
 *   - password -> NOT here: the LeakLens audit endpoint is an HIBP range proxy;
 *                 PwnedPasswordsSource already queries HIBP directly and the
 *                 dashboard's client-side matcher is keyed to that source
 *   - domain   -> NOT here: EC surfaces domain infrastructure only (crt.sh + RDAP);
 *                 website scanning stays in the scanner CE (owner scope rule)
 *
 * MCP envelope: {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":...}}
 * Inner payload: {"isExposed":bool,"exposedCount":int,"results":[...],
 *                 "degraded":bool,"errors":["upstream",...]}
 *
 * Honest-degradation rule (their semantics meet ours):
 *   isExposed=true            -> hit (a hit is a hit even if some upstreams errored)
 *   isExposed=false, degraded=false -> clean
 *   isExposed=false, degraded=true  -> UNAVAILABLE — upstreams errored, so a "not
 *   found" cannot be trusted; never fake a clean pass (platform rule).
 *
 * License note: leaklens.org registry data is free for non-commercial, civic and
 * human-rights use — fine for this self-hosted personal checker; it is NOT licensed
 * for the commercial platform, which is why this source ships only in the CE.
 *
 * ETHICS: aggregates only — breach/database names, dates, record counts. Any
 * credential-like or third-party-identity fields in result items are dropped.
 */
class LeakLensSource implements OsintSource
{
    private const MCP = 'https://leaklens.org/api/mcp';

    private const TOOLS = [
        'phone' => 'search_phone',
        'username' => 'search_username',
    ];

    public function key(): string
    {
        return 'leaklens';
    }

    public function label(): string
    {
        return 'LeakLens — Breach Registry Search';
    }

    public function category(): string
    {
        return 'breach';
    }

    public function supports(string $type): bool
    {
        return isset(self::TOOLS[$type]);
    }

    public function requests(string $type, string $identifier): array
    {
        if (!isset(self::TOOLS[$type])) {
            return [];
        }

        $arguments = ['username' => $identifier];
        if ($type === 'phone') {
            // their tool expects international format (e.g. +8801712345678);
            // normalize() gives bare digits, so re-add the plus
            $arguments = ['phone' => '+' . ltrim($identifier, '+')];
        }

        $payload = json_encode([
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'tools/call',
            'params' => [
                'name' => self::TOOLS[$type],
                'arguments' => (object) $arguments,
            ],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'POST',
                'url' => self::MCP,
                'headers' => [
                    'Accept' => 'application/json, text/event-stream',
                    'Content-Type' => 'application/json',
                ],
                'body' => $payload,
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'LeakLens breach search unavailable right now.', 'data' => []];
        }

        $envelope = $resp->json();
        $text = $envelope['result']['content'][0]['text'] ?? null;
        if (!is_string($text) || $text === '') {
            return ['status' => 'unavailable', 'summary' => 'LeakLens returned an unexpected response.', 'data' => []];
        }
        if (!empty($envelope['result']['isError'])) {
            return ['status' => 'unavailable', 'summary' => 'LeakLens could not run this search.', 'data' => []];
        }

        $inner = json_decode($text, true);
        if (!is_array($inner)) {
            return ['status' => 'unavailable', 'summary' => 'LeakLens returned an unreadable result.', 'data' => []];
        }

        $exposed = (bool) ($inner['isExposed'] ?? false);
        $count = (int) ($inner['exposedCount'] ?? 0);
        $degraded = (bool) ($inner['degraded'] ?? false);
        $errors = [];
        foreach ((array) ($inner['errors'] ?? []) as $e) {
            if (is_string($e) && $e !== '') {
                $errors[] = $e;
            }
        }

        // ---- HIT: aggregates only, credential-like fields dropped ----
        if ($exposed) {
            $records = [];
            $raw = is_array($inner['results'] ?? null) ? $inner['results'] : [];
            foreach ($raw as $r) {
                if (is_string($r) && trim($r) !== '') {
                    $records[] = trim($r);
                    if (count($records) >= 10) {
                        break;
                    }
                    continue;
                }
                if (!is_array($r)) {
                    continue;
                }
                $name = $this->firstString($r, ['breach', 'name', 'source', 'title', 'database']);
                $date = $this->firstString($r, ['date', 'xposed_date', 'year', 'breach_date']);
                $rec = $r['records'] ?? $r['count'] ?? $r['exposed_records'] ?? null;
                $line = $name;
                if ($date !== '') {
                    $line .= ($line !== '' ? ' — ' : '') . $date;
                }
                if (is_numeric($rec) && (int) $rec > 0) {
                    $line .= ($line !== '' ? ' — ' : '') . number_format((int) $rec) . ' records';
                }
                if ($line !== '') {
                    $records[] = $line;
                }
                if (count($records) >= 10) {
                    break;
                }
            }
            $shown = $count > 0 ? $count : count($records);

            $data = [
                'exposures' => $shown,
                'records' => $records,
                'note' => 'Aggregate breach-registry records via leaklens.org (non-commercial civic registry).',
            ];
            if ($errors !== []) {
                $data['degraded_upstreams'] = implode(', ', $errors) . ' (partial coverage)';
            }

            $summary = 'FOUND in ' . $shown . ' breach registry record(s)'
                . ($errors !== [] ? ' — partial: some upstream sources did not answer' : '') . '.';

            return [
                'status' => 'hit',
                'summary' => $summary,
                'severity' => 'high',
                'data' => $data,
            ];
        }

        // ---- not exposed: only trust it when nothing degraded ----
        if ($degraded) {
            $why = $errors !== [] ? ' (' . implode(', ', $errors) . ' did not answer)' : '';
            return [
                'status' => 'unavailable',
                'summary' => 'LeakLens could not verify — upstream sources degraded' . $why . '.',
                'data' => [],
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'No exposure records found for this identifier.',
            'severity' => 'info',
            'data' => [
                'exposures' => 0,
                'note' => 'This identifier does not appear in the LeakLens breach registry.',
            ],
        ];
    }

    /** First non-empty string value among the given keys. */
    private function firstString(array $row, array $keys): string
    {
        foreach ($keys as $k) {
            $v = $row[$k] ?? null;
            if (is_string($v) && trim($v) !== '') {
                return trim($v);
            }
        }

        return '';
    }
}
