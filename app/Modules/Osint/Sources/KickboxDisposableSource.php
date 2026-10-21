<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Kickbox Open Disposable (open.kickbox.com) - keyless disposable corroboration.
 * GET https://open.kickbox.com/v1/disposable/{email-or-domain} -> {"disposable":bool}
 *
 * Second independent source beside Disify/Facha: clean yes/no disposable
 * verdict from Kickbox's openly published list. R6-B live-verified 2026-10-20.
 */
class KickboxDisposableSource implements OsintSource
{
    private const URL = 'https://open.kickbox.com/v1/disposable/';

    public function key(): string
    {
        return 'kickbox_disposable';
    }

    public function label(): string
    {
        return 'Kickbox Open — Disposable Check';
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
            return ['status' => 'unavailable', 'summary' => 'Kickbox disposable check unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j) || !array_key_exists('disposable', $j)) {
            return ['status' => 'unavailable', 'summary' => 'Kickbox returned an unexpected response.', 'data' => []];
        }

        $disposable = (bool) $j['disposable'];

        if ($disposable) {
            return [
                'status' => 'hit',
                'severity' => 'medium',
                'summary' => 'Kickbox confirms this address uses a disposable/temporary email domain.',
                'data' => ['disposable' => true],
            ];
        }

        return [
            'status' => 'clean',
            'severity' => 'info',
            'summary' => 'Kickbox: not a disposable email address.',
            'data' => ['disposable' => false],
        ];
    }
}
