<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Disify (disify.com) - keyless email intelligence.
 * GET https://www.disify.com/api/email/{email} ->
 * {"format":true,"domain":"...","disposable":false,"dns":true,"mx_info":[...],
 *  "role":true,"free":false,"confidence":0,"signals":[...]}
 *
 * Richer than a plain disposable check: MX hosts, role-account flag,
 * free-provider flag and a confidence score. Category: email intelligence.
 * R6-B live-verified 2026-10-20 (keyless, JSON).
 */
class DisifySource implements OsintSource
{
    private const URL = 'https://www.disify.com/api/email/';

    public function key(): string
    {
        return 'disify';
    }

    public function label(): string
    {
        return 'Disify — Email Intelligence';
    }

    public function category(): string
    {
        return 'email';
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }

    public function requests(string $type, string $identifier): array
    {
        if (!filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . urlencode($identifier),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Disify email intelligence unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'Disify returned an unexpected response.', 'data' => []];
        }

        $disposable = (bool) ($j['disposable'] ?? false);
        $role = (bool) ($j['role'] ?? false);
        $free = (bool) ($j['free'] ?? false);
        $mx = is_array($j['mx_info'] ?? null) ? $j['mx_info'] : [];
        $confidence = isset($j['confidence']) ? (int) $j['confidence'] : null;

        $data = [
            'disposable' => $disposable,
            'role_account' => $role,
            'free_provider' => $free,
            'mx_hosts' => array_slice(array_map('strval', $mx), 0, 4),
            'confidence' => $confidence,
        ];

        if ($disposable) {
            return [
                'status' => 'hit',
                'severity' => 'medium',
                'summary' => 'Disify flags this address as a disposable/temporary email provider.',
                'data' => $data,
            ];
        }

        $notes = [];
        if ($role) {
            $notes[] = 'a role/group account (shared mailbox)';
        }
        if ($free) {
            $notes[] = 'a free consumer email provider';
        }
        if ($notes !== []) {
            return [
                'status' => 'hit',
                'severity' => 'low',
                'summary' => 'Disify classifies this address as ' . implode(' and ', $notes) . '.',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'severity' => 'info',
            'summary' => 'Disify: valid format'
                . ($mx !== [] ? ', MX records present (' . $data['mx_hosts'][0] . ')' : '')
                . ', not disposable, not a role account.',
            'data' => $data,
        ];
    }
}
